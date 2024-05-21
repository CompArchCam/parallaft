use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        syscall::{
            StandardSyscallEntryCheckerHandlerExitAction,
            StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
        },
        HandlerContext,
    },
    types::segment_record::saved_syscall::{
        SavedIncompleteSyscall, SavedIncompleteSyscallKind, SyscallExitAction,
    },
};

pub struct ExitHandler {}

impl Default for ExitHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ExitHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for ExitHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _context: HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        Ok(match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                    SavedIncompleteSyscall {
                        syscall: *syscall,
                        kind: SavedIncompleteSyscallKind::WithoutMemoryEffects,
                        exit_action: SyscallExitAction::Custom,
                    },
                )
            }
            _ => StandardSyscallEntryMainHandlerExitAction::NextHandler,
        })
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        _context: HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        Ok(match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                // TODO: check exit syscall
                StandardSyscallEntryCheckerHandlerExitAction::Checkpoint
            }
            _ => StandardSyscallEntryCheckerHandlerExitAction::NextHandler,
        })
    }
    // Exit syscall never exits
}

impl Module for ExitHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
