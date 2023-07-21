use std::os::fd::AsRawFd;

use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Dispatcher, Installable},
    error::Result,
    inferior_rtlib::{ScheduleCheckpoint, ScheduleCheckpointReady},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{HandlerContext, ProcessLifetimeHook},
};
use libfpt_rs::{FptFd, FptFlags, TRAP_FPT_FULL, TRAP_FPT_WATERMARK, TRAP_FPT_WATERMARK_USER};
use log::info;
use nix::sys::{ptrace, signal::Signal};
use parking_lot::Mutex;

/// Schedule a checkpoint to be taken as soon as possible after the main process writes enough memory.
pub struct CheckpointSizeLimiter {
    size_watermark: usize,
    fpt_fd: Mutex<Option<FptFd>>,
}

impl CheckpointSizeLimiter {
    pub fn new(size_watermark: usize) -> Self {
        Self {
            size_watermark,
            fpt_fd: Mutex::new(None),
        }
    }
}

impl ProcessLifetimeHook for CheckpointSizeLimiter {
    fn handle_main_fini(&self, _ret_val: i32) -> Result<()> {
        if self.size_watermark == 0 {
            return Ok(());
        }

        let mut fpt_fd = self.fpt_fd.lock();
        fpt_fd.take().map(drop);

        Ok(())
    }
}

impl SignalHandler for CheckpointSizeLimiter {
    fn handle_signal(
        &self,
        signal: Signal,
        context: &HandlerContext,
    ) -> Result<SignalHandlerExitAction> {
        if signal == Signal::SIGTRAP {
            let siginfo = ptrace::getsiginfo(context.process.pid)?;
            match siginfo.si_code {
                TRAP_FPT_FULL | TRAP_FPT_WATERMARK | TRAP_FPT_WATERMARK_USER => {
                    info!("Trap: FPT");
                    let mut fpt_fd_mg = self.fpt_fd.lock();
                    let fpt_fd = fpt_fd_mg.as_mut().unwrap();

                    fpt_fd.clear_fault().unwrap();

                    context
                        .check_coord
                        .dispatcher
                        .schedule_checkpoint(context.check_coord)
                        .unwrap();

                    return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior);
                }
                _ => (),
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ScheduleCheckpointReady for CheckpointSizeLimiter {
    fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()> {
        if self.size_watermark == 0 {
            return Ok(());
        }

        let mut fd = FptFd::new(
            check_coord.main.pid,
            self.size_watermark * 2,
            FptFlags::EXCLUDE_NON_WRITABLE_VMA
                | FptFlags::SIGTRAP_WATERMARK
                | FptFlags::SIGTRAP_WATERMARK_USER,
            Some(self.size_watermark),
        )
        .unwrap();

        fd.enable().unwrap();

        info!(
            "Checkpoint size limiter initialized, fpt fd = {}",
            fd.as_raw_fd()
        );

        *self.fpt_fd.lock() = Some(fd);

        Ok(())
    }
}

impl<'a> Installable<'a> for CheckpointSizeLimiter {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
        dispatcher.install_signal_handler(self);
        dispatcher.install_schedule_checkpoint_ready_handler(self);
    }
}
