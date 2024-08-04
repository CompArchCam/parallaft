use std::{
    os::fd::AsRawFd,
    sync::atomic::{AtomicU64, Ordering},
};

use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContext,
    },
    inferior_rtlib::{ScheduleCheckpoint, ScheduleCheckpointReady},
    statistics::{StatisticValue, StatisticsProvider},
    statistics_list,
    types::{exit_reason::ExitReason, process_id::Main},
};
use libfpt_rs::{FptFd, FptFlags, TRAP_FPT_WATERMARK_USER};
use log::info;
use nix::sys::{ptrace, signal::Signal};
use parking_lot::Mutex;

/// Schedule a checkpoint to be taken as soon as possible after the main process writes enough memory.
pub struct CheckpointSizeLimiter {
    size_watermark: usize,
    fpt_fd: Mutex<Option<FptFd>>,
    num_triggers: AtomicU64,
}

impl CheckpointSizeLimiter {
    pub fn new(size_watermark: usize) -> Self {
        Self {
            size_watermark,
            fpt_fd: Mutex::new(None),
            num_triggers: AtomicU64::new(0),
        }
    }
}

impl ProcessLifetimeHook for CheckpointSizeLimiter {
    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        _main: &mut Main,
        _exit_reason: &ExitReason,
        _context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        if self.size_watermark == 0 {
            return Ok(());
        }

        let mut fpt_fd = self.fpt_fd.lock();
        if let Some(a) = fpt_fd.take() {
            drop(a)
        }

        Ok(())
    }
}

impl SignalHandler for CheckpointSizeLimiter {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGTRAP {
            let siginfo = ptrace::getsiginfo(context.process().pid)?;

            if siginfo.si_code == TRAP_FPT_WATERMARK_USER {
                info!("Trap: FPT");
                self.num_triggers.fetch_add(1, Ordering::SeqCst);

                context
                    .check_coord
                    .dispatcher
                    .schedule_checkpoint(context.child.unwrap_main_mut(), context.check_coord)
                    .unwrap();

                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                    single_step: false,
                });
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl SegmentEventHandler for CheckpointSizeLimiter {
    fn handle_segment_created(&self, _main: &mut Main) -> Result<()> {
        if let Some(fd) = self.fpt_fd.lock().as_mut() {
            fd.clear_fault().unwrap()
        }

        Ok(())
    }

    fn handle_segment_chain_closed(&self, _main: &mut Main) -> Result<()> {
        if let Some(fd) = self.fpt_fd.lock().as_mut() {
            fd.clear_fault().unwrap()
        }

        Ok(())
    }
}

impl ScheduleCheckpointReady for CheckpointSizeLimiter {
    fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()> {
        if self.size_watermark == 0 {
            return Ok(());
        }

        let mut fd = FptFd::new(
            check_coord.main_pid,
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

impl StatisticsProvider for CheckpointSizeLimiter {
    fn class_name(&self) -> &'static str {
        "checkpoint_size_limiter"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        statistics_list!(num_triggers = self.num_triggers.load(Ordering::SeqCst))
    }
}

impl Module for CheckpointSizeLimiter {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_signal_handler(self);
        subs.install_schedule_checkpoint_ready_handler(self);
        subs.install_segment_event_handler(self);
        subs.install_stats_providers(self);
    }
}
