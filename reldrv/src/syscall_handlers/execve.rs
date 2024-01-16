use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    segments::Segment,
};

use super::{HandlerContext, StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler};

pub struct ExecveHandler {}

impl ExecveHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for ExecveHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _active_segment: &mut Segment,
        _context: &HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) {
            panic!("Execve(at) is disallowed in protected regions");
        }

        Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler)
    }
}

impl Module for ExecveHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
