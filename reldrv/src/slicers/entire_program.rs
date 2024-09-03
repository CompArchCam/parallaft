use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::state::Stopped,
    signal_handlers::begin_protection::main_begin_protection_req,
    syscall_handlers::is_execve_ok,
};

pub struct EntireProgramSlicer;

impl EntireProgramSlicer {
    pub fn new() -> Self {
        Self
    }
}

impl StandardSyscallHandler for EntireProgramSlicer {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            assert!(context.child.is_main());
            main_begin_protection_req(context.child.process())?;
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for EntireProgramSlicer {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
