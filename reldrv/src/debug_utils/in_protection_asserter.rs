use crate::{
    dispatcher::Module, events::syscall::CustomSyscallHandler, process::state::Stopped,
    types::custom_sysno::CustomSysno,
};

pub struct InProtectionAsserter;

impl CustomSyscallHandler for InProtectionAsserter {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: crate::events::HandlerContext<Stopped>,
    ) -> crate::error::Result<crate::events::syscall::SyscallHandlerExitAction> {
        if CustomSysno::from_repr(sysno) == Some(CustomSysno::AssertInProtection) {
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
