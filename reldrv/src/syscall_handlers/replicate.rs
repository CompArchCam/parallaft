use log::error;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        syscall::{
            StandardSyscallEntryCheckerHandlerExitAction,
            StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
        },
        HandlerContextWithInferior,
    },
    process::state::Stopped,
    types::segment_record::saved_syscall::{
        SavedIncompleteSyscall, SavedIncompleteSyscallKind, SyscallExitAction,
    },
};

pub struct ReplicatedSyscallHandler {}

impl Default for ReplicatedSyscallHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ReplicatedSyscallHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for ReplicatedSyscallHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _context: HandlerContextWithInferior<Stopped>,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        let action = || {
            StandardSyscallEntryMainHandlerExitAction::StoreSyscall(SavedIncompleteSyscall {
                syscall: *syscall,
                kind: SavedIncompleteSyscallKind::WithoutMemoryEffects,
                exit_action: SyscallExitAction::ReplicateSyscall,
            })
        };

        Ok(match syscall {
            #[cfg(target_arch = "x86_64")]
            Syscall::ArchPrctl(_) => action(),
            Syscall::Brk(_)
            | Syscall::RtSigreturn(_)
            | Syscall::Exit(_)
            | Syscall::ExitGroup(_) => action(),
            _ => StandardSyscallEntryMainHandlerExitAction::NextHandler,
        })
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        let action_complete_syscall = || {
            let saved_syscall = context
                .child
                .unwrap_checker()
                .segment
                .record
                .get_syscall()?;

            if &saved_syscall.syscall != syscall {
                error!(
                    "Unexpected syscall {:?}, expecting {:?}",
                    syscall, saved_syscall.syscall
                );

                return Err(Error::UnexpectedEvent(
                    UnexpectedEventReason::IncorrectValue,
                ));
            }

            Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
        };

        let action_incomplete_syscall = || {
            let saved_syscall = context
                .child
                .unwrap_checker()
                .segment
                .record
                .pop_incomplete_syscall()?;

            if &saved_syscall.value.syscall != syscall {
                error!(
                    "Unexpected syscall {:?}, expecting {:?}",
                    syscall, saved_syscall.value.syscall
                );

                return Err(Error::UnexpectedEvent(
                    UnexpectedEventReason::IncorrectValue,
                ));
            }

            Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
        };

        match syscall {
            #[cfg(target_arch = "x86_64")]
            Syscall::ArchPrctl(_) => action_complete_syscall(),
            Syscall::Brk(_) | Syscall::RtSigreturn(_) => action_complete_syscall(),
            Syscall::Exit(_) | Syscall::ExitGroup(_) => action_incomplete_syscall(),
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
