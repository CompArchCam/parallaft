use reverie_syscalls::{Syscall, SyscallInfo};

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::Result,
    saved_syscall::{SavedIncompleteSyscall, SavedIncompleteSyscallKind, SyscallExitAction},
    segments::Segment,
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
        _active_segment: &mut Segment,
        _context: &HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        Ok(match syscall {
            Syscall::ArchPrctl(_) | Syscall::Brk(_) | Syscall::Mprotect(_) | Syscall::Munmap(_) => {
                StandardSyscallEntryMainHandlerExitAction::StoreSyscall(SavedIncompleteSyscall {
                    syscall: *syscall,
                    kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                    exit_action: SyscallExitAction::ReplicateSyscall,
                })
            }
            _ => StandardSyscallEntryMainHandlerExitAction::NextHandler,
        })
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        _context: &HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        Ok(match syscall {
            Syscall::ArchPrctl(_) | Syscall::Brk(_) | Syscall::Mprotect(_) | Syscall::Munmap(_) => {
                let saved_syscall = active_segment
                    .syscall_log
                    .front()
                    .expect("spurious syscall made by checker");

                assert_eq!(saved_syscall.syscall.into_parts(), syscall.into_parts());

                StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior
            }
            _ => StandardSyscallEntryCheckerHandlerExitAction::NextHandler,
        })
    }

    // Exit syscall never exits
}

impl<'a> Installable<'a> for ReplicatedSyscallHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
    }
}
