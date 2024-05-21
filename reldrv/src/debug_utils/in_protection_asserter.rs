use crate::{
    dispatcher::Module, events::syscall::CustomSyscallHandler, syscall_handlers::CUSTOM_SYSNO_START,
};

pub const SYSNO_ASSERT_IN_PROTECTION: usize = CUSTOM_SYSNO_START + 3;

pub struct InProtectionAsserter;

impl CustomSyscallHandler for InProtectionAsserter {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: crate::events::HandlerContext,
    ) -> crate::error::Result<crate::events::syscall::SyscallHandlerExitAction> {
        if sysno == SYSNO_ASSERT_IN_PROTECTION {
            assert!(
                context.child.segment().is_some(),
                "Assertion failed: in protection zone"
            );
        }
        Ok(crate::events::syscall::SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for InProtectionAsserter {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_custom_syscall_handler(self);
    }
}
