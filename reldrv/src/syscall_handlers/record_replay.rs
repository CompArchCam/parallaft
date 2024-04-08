use nix::sys::uio::RemoteIoVec;
use reverie_syscalls::{
    may_rw::{SyscallMayRead, SyscallMayWrite},
    Syscall,
};

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    types::segment_record::{
        saved_memory::SavedMemory,
        saved_syscall::{
            SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedSyscallKind, SyscallExitAction,
        },
    },
};

use super::{
    HandlerContext, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
};

pub struct RecordReplaySyscallHandler {}

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
        let process = context.process();

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
                        kind: SavedIncompleteSyscallKind::KnownMemoryRAndWRange {
                            mem_read: SavedMemory::save(process, &may_read)?,
                            mem_written_ranges: may_write,
                        },
                        exit_action: SyscallExitAction::ReplicateMemoryWrites,
                    },
                ))
            }
            _ => {
                // otherwise, take a full checkpoint right before the syscall and another right after the syscall
                todo!("handle syscall with unknown memory effects")
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
        let process = context.process();

        let active_segment = context.child.unwrap_checker_segment();

        // Skip the syscall
        process.modify_registers_with(|regs| regs.with_syscall_skipped())?;

        if let Some(saved_syscall) = active_segment.record.peek_syscall() {
            if &saved_syscall.syscall != syscall {
                return Err(Error::UnexpectedSyscall(
                    UnexpectedEventReason::IncorrectTypeOrArguments,
                ));
            }

            match &saved_syscall.kind {
                SavedSyscallKind::UnknownMemoryRw => {
                    Ok(StandardSyscallEntryCheckerHandlerExitAction::Checkpoint)
                }
                SavedSyscallKind::KnownMemoryRw { mem_read, .. } => {
                    // compare memory read by the syscall
                    if !mem_read.compare(process)? {
                        return Err(Error::UnexpectedSyscall(
                            UnexpectedEventReason::IncorrectMemory,
                        ));
                    }
                    Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
                }
            }
        } else if let Some(incomplete_syscall) = &active_segment.record.ongoing_syscall {
            if &incomplete_syscall.syscall != syscall {
                return Err(Error::UnexpectedSyscall(
                    UnexpectedEventReason::IncorrectTypeOrArguments,
                ));
            }

            todo!()
        } else {
            Err(Error::UnexpectedSyscall(UnexpectedEventReason::Excess))
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
