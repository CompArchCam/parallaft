use reverie_syscalls::Syscall;

use crate::dispatcher::{Module, Subscribers};
use crate::error::{Error, Result};

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
        _context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        #[cfg(target_arch = "x86_64")]
        if matches!(
            syscall,
            Syscall::Fork(_) | Syscall::Vfork(_) | Syscall::Clone(_) | Syscall::Clone3(_)
        ) {
            return Err(Error::NotSupported(
                "fork/vfork/clone/clone3 is disallowed".to_string(),
            ));
        }

        #[cfg(target_arch = "aarch64")]
        if matches!(syscall, Syscall::Clone(_) | Syscall::Clone3(_)) {
            return Err(Error::NotSupported(
                "clone/clone3 is disallowed".to_string(),
            ));
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for CloneHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
