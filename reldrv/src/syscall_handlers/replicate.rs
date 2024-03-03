use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    saved_syscall::{SavedIncompleteSyscall, SavedIncompleteSyscallKind, SyscallExitAction},
};

use super::{
    HandlerContext, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
};

pub struct ReplicatedSyscallHandler {}

impl ReplicatedSyscallHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for ReplicatedSyscallHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _context: HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        let action = || {
            StandardSyscallEntryMainHandlerExitAction::StoreSyscall(SavedIncompleteSyscall {
                syscall: *syscall,
                kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                exit_action: SyscallExitAction::ReplicateSyscall,
            })
        };

        Ok(match syscall {
            #[cfg(target_arch = "x86_64")]
            Syscall::ArchPrctl(_) => action(),
            Syscall::Brk(_) | Syscall::Mprotect(_) | Syscall::Munmap(_) => action(),
            _ => StandardSyscallEntryMainHandlerExitAction::NextHandler,
        })
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        let action = || {
            let saved_syscall = context
                .child
                .unwrap_checker_segment()
                .replay
                .syscall_log
                .front()
                .ok_or(Error::UnexpectedSyscall(UnexpectedEventReason::Excess))?;

            if &saved_syscall.syscall != syscall {
                return Err(Error::UnexpectedSyscall(
                    UnexpectedEventReason::IncorrectTypeOrArguments,
                ));
            }

            Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
        };

        match syscall {
            #[cfg(target_arch = "x86_64")]
            Syscall::ArchPrctl(_) => action(),
            Syscall::Brk(_) | Syscall::Mprotect(_) | Syscall::Munmap(_) => action(),
            _ => Ok(StandardSyscallEntryCheckerHandlerExitAction::NextHandler),
        }
    }

    // Exit syscall never exits
}

impl Module for ReplicatedSyscallHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
