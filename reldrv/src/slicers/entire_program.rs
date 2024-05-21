use log::info;
use nix::sys::signal::Signal;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    syscall_handlers::is_execve_ok,
    types::process_id::InferiorRefMut,
};

pub struct EntireProgramSlicer;

impl EntireProgramSlicer {
    const SIGVAL_DO_CHECKPOINT: usize = 0x610aa619b2490fa2;

    pub fn new() -> Self {
        Self
    }
}

impl StandardSyscallHandler for EntireProgramSlicer {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            assert!(context.child.is_main());

            context
                .child
                .process()
                .sigqueue(Self::SIGVAL_DO_CHECKPOINT)?;
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for EntireProgramSlicer {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        if let InferiorRefMut::Main(main) = context.child {
            if main.process.get_sigval()? == Some(Self::SIGVAL_DO_CHECKPOINT) {
                info!("{main} Taking initial checkpoint");
                return Ok(SignalHandlerExitAction::Checkpoint);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl Module for EntireProgramSlicer {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_signal_handler(self);
    }
}
