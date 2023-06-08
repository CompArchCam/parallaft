use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Dispatcher, Installable},
    saved_syscall::{SavedIncompleteSyscall, SavedIncompleteSyscallKind, SyscallExitAction},
    segments::Segment,
};

use super::{
    HandlerContext, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
};

pub struct ExitHandler {}

impl ExitHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for ExitHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _active_segment: &mut Segment,
        _context: &HandlerContext,
    ) -> StandardSyscallEntryMainHandlerExitAction {
        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                    SavedIncompleteSyscall {
                        syscall: *syscall,
                        kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                        exit_action: SyscallExitAction::Custom,
                    },
                )
            }
            _ => StandardSyscallEntryMainHandlerExitAction::NextHandler,
        }
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        _context: &HandlerContext,
    ) -> StandardSyscallEntryCheckerHandlerExitAction {
        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                assert_eq!(
                    &active_segment.ongoing_syscall.as_ref().unwrap().syscall,
                    syscall
                );
                StandardSyscallEntryCheckerHandlerExitAction::Checkpoint
            }
            _ => StandardSyscallEntryCheckerHandlerExitAction::NextHandler,
        }
    }

    // Exit syscall never exits
}

impl<'a> Installable<'a> for ExitHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
    }
}
