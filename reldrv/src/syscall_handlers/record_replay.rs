use std::ops::Deref;

use log::error;
use nix::sys::uio::RemoteIoVec;
use reverie_syscalls::{
    may_rw::{SyscallMayRead, SyscallMayWrite},
    Syscall,
};

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        syscall::{
            StandardSyscallEntryCheckerHandlerExitAction,
            StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
        },
        HandlerContext,
    },
    process::registers::RegisterAccess,
    types::segment_record::{
        saved_memory::SavedMemory,
        saved_syscall::{
            SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedSyscallKind, SyscallExitAction,
        },
    },
};

pub struct RecordReplaySyscallHandler {}

impl Default for RecordReplaySyscallHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RecordReplaySyscallHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for RecordReplaySyscallHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        let process = context.process().deref();

        let may_read = syscall.may_read(process).ok().map(|slices| {
            slices
                .iter()
                .map(|slice| RemoteIoVec {
                    base: unsafe { slice.as_ptr() as _ },
                    len: slice.len(),
                })
                .collect::<Box<[RemoteIoVec]>>()
        });

        let may_write = syscall.may_write(process).ok().map(|slices| {
            slices
                .iter()
                .map(|slice| RemoteIoVec {
                    base: unsafe { slice.as_ptr() as _ },
                    len: slice.len(),
                })
                .collect::<Box<[RemoteIoVec]>>()
        });

        match (may_read, may_write) {
            (Some(may_read), Some(may_write)) => {
                // we know the exact memory r/w of the syscall
                Ok(StandardSyscallEntryMainHandlerExitAction::StoreSyscall(
                    SavedIncompleteSyscall {
                        syscall: *syscall,
                        kind: SavedIncompleteSyscallKind::WithMemoryEffects {
                            mem_read: SavedMemory::save(process, &may_read)?,
                            mem_written_ranges: may_write,
                        },
                        exit_action: SyscallExitAction::ReplayEffects,
                    },
                ))
            }
            _ => {
                // otherwise, take a full checkpoint right before the syscall and another right after the syscall
                return Err(Error::NotSupported(
                    "Handling syscall with unknown memory effects is not yet supported".to_string(),
                ));
                // Ok(
                //     StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                //         SavedIncompleteSyscall {
                //             syscall: *syscall,
                //             kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                //             exit_action: SyscallExitAction::Checkpoint,
                //         },
                //     ),
                // )
            }
        }
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        let checker = context.child.unwrap_checker();

        // Skip the syscall
        checker
            .process
            .modify_registers_with(|regs| regs.with_syscall_skipped())?;

        if let Ok(saved_syscall) = checker.segment.record.get_syscall() {
            if &saved_syscall.syscall != syscall {
                error!(
                    "Unexpected syscall {:?}, expecting {:?}",
                    syscall, saved_syscall.syscall
                );

                return Err(Error::UnexpectedEvent(
                    UnexpectedEventReason::IncorrectValue,
                ));
            }

            match &saved_syscall.kind {
                SavedSyscallKind::WithoutMemoryEffects => {
                    Ok(StandardSyscallEntryCheckerHandlerExitAction::Checkpoint)
                }
                SavedSyscallKind::WithMemoryEffects { mem_read, .. } => {
                    // compare memory read by the syscall
                    if !mem_read.compare(checker.process.deref())? {
                        return Err(Error::UnexpectedEvent(
                            UnexpectedEventReason::IncorrectMemory,
                        ));
                    }
                    Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
                }
            }
        } else if let Ok(incomplete_syscall) = checker.segment.record.get_incomplete_syscall() {
            if &incomplete_syscall.syscall != syscall {
                error!(
                    "Unexpected syscall {:?}, expecting {:?}",
                    syscall, incomplete_syscall.syscall
                );

                return Err(Error::UnexpectedEvent(
                    UnexpectedEventReason::IncorrectValue,
                ));
            }

            todo!()
        } else {
            Err(Error::UnexpectedEvent(UnexpectedEventReason::Excess))
        }
    }

    // Exit syscall never exits
}

impl Module for RecordReplaySyscallHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
