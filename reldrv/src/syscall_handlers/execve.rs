use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Dispatcher, Installable},
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
    ) -> StandardSyscallEntryMainHandlerExitAction {
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) {
            panic!("Execve(at) is disallowed in protected regions");
        }

        StandardSyscallEntryMainHandlerExitAction::NextHandler
    }
}

impl<'a> Installable<'a> for ExecveHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
    }
}
