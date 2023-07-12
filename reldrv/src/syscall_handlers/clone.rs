use reverie_syscalls::Syscall;

use crate::dispatcher::{Dispatcher, Installable};
use crate::error::Result;

use super::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction};

pub struct CloneHandler {}

impl CloneHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for CloneHandler {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        _context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if matches!(
            syscall,
            Syscall::Fork(_) | Syscall::Vfork(_) | Syscall::Clone(_) | Syscall::Clone3(_)
        ) {
            panic!("fork/vfork/clone/clone3 is disallowed");
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> Installable<'a> for CloneHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
    }
}
