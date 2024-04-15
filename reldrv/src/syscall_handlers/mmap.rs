use std::{collections::HashSet, ops::Range};

use log::{error, info};
use parking_lot::Mutex;
use reverie_syscalls::{Addr, AddrMut, MapFlags, ProtFlags, Syscall, SyscallInfo};

use crate::{
    dirty_page_trackers::ExtraWritableRangesProvider,
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        syscall::{
            StandardSyscallEntryCheckerHandlerExitAction,
            StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
            SyscallHandlerExitAction,
        },
        HandlerContext,
    },
    types::segment_record::saved_syscall::{
        SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedSyscall, SyscallExitAction,
    },
};

pub struct MmapHandler {
    extra_writable_ranges: Mutex<HashSet<Range<usize>>>,
}

impl Default for MmapHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl MmapHandler {
    pub fn new() -> Self {
        Self {
            extra_writable_ranges: Mutex::new(HashSet::new()),
        }
    }
}

impl StandardSyscallHandler for MmapHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        let syscall = *syscall;
        let main = context.process();

        match syscall {
            Syscall::Mmap(mut mmap) => {
                // HACK
                // if mmap.flags().contains(MapFlags::MAP_SHARED) {
                //     mmap = mmap.with_prot(mmap.prot() & !ProtFlags::PROT_WRITE);
                // }

                mmap = mmap.with_flags(
                    (mmap.flags() & !MapFlags::MAP_SHARED) | MapFlags::MAP_PRIVATE, // TODO: MAP_SHARED_VALIDATE
                );

                // if mmap.flags().contains(MapFlags::MAP_SHARED)
                //     && mmap.prot().contains(ProtFlags::PROT_WRITE)
                // {
                //     panic!("Unsupported MAP_SHARED and PROT_WRITE combination");
                // }

                if !mmap.flags().contains(MapFlags::MAP_ANONYMOUS) {
                    // File-backed mmap

                    if mmap.fd() >= 0 {
                        main.modify_registers_with(|regs| {
                            regs.with_syscall_args(mmap.into_parts().1)
                        })?;

                        Ok(
                            StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                                SavedIncompleteSyscall {
                                    syscall,
                                    kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                                    exit_action: SyscallExitAction::Checkpoint,
                                },
                            ),
                        )
                    } else {
                        panic!("Mmap unexpected fd");
                    }
                } else {
                    main.modify_registers_with(|regs| regs.with_syscall_args(mmap.into_parts().1))?;

                    Ok(StandardSyscallEntryMainHandlerExitAction::StoreSyscall(
                        SavedIncompleteSyscall {
                            syscall,
                            kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                            exit_action: SyscallExitAction::Custom,
                        },
                    ))
                }
            }
            Syscall::Mremap(_) => Ok(StandardSyscallEntryMainHandlerExitAction::StoreSyscall(
                SavedIncompleteSyscall {
                    syscall,
                    kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                    exit_action: SyscallExitAction::Custom,
                },
            )),
            _ => Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler),
        }
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        let syscall = *syscall;
        let active_segment = context.child.unwrap_checker_segment();

        match syscall {
            Syscall::Mmap(mmap) => {
                // checker process
                // use MAP_FIXED, mapping exactly the same address that the main process did

                if !mmap.flags().contains(MapFlags::MAP_ANONYMOUS) {
                    info!("Checker mmap checkpoint fini");
                    // File-backed mmap

                    if mmap.fd() >= 0 {
                        Ok(StandardSyscallEntryCheckerHandlerExitAction::Checkpoint)
                    } else {
                        panic!("Unexpected fd")
                    }
                } else {
                    let saved_syscall = active_segment
                        .record
                        .peek_syscall()
                        .ok_or(Error::UnexpectedSyscall(UnexpectedEventReason::Excess))?;

                    if saved_syscall.syscall != syscall {
                        error!("Mmap syscall mismatch");
                        return Err(Error::UnexpectedSyscall(
                            UnexpectedEventReason::IncorrectTypeOrArguments,
                        ));
                    }

                    if saved_syscall.ret_val != nix::libc::MAP_FAILED as _ {
                        // rewrite only if mmap has succeeded
                        if !mmap.flags().contains(MapFlags::MAP_FIXED)
                            && !mmap.flags().contains(MapFlags::MAP_FIXED_NOREPLACE)
                        {
                            let mmap = mmap
                                .with_addr(Addr::from_raw(saved_syscall.ret_val as _))
                                .with_flags(mmap.flags() | MapFlags::MAP_FIXED_NOREPLACE);

                            let (new_sysno, new_args) = mmap.into_parts();
                            active_segment
                                .checker
                                .process()
                                .unwrap()
                                .modify_registers_with(|regs| {
                                    regs.with_sysno(new_sysno).with_syscall_args(new_args)
                                })?;
                        }
                    }

                    Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
                }
            }
            Syscall::Mremap(mut mremap) => {
                let saved_syscall = active_segment
                    .record
                    .peek_syscall()
                    .ok_or(Error::UnexpectedSyscall(UnexpectedEventReason::Excess))?;

                if saved_syscall.syscall != syscall {
                    info!("Mremap syscall mismatch");
                    return Err(Error::UnexpectedSyscall(
                        UnexpectedEventReason::IncorrectTypeOrArguments,
                    ));
                }

                // rewrite only if mmap has succeeded
                if saved_syscall.ret_val != nix::libc::MAP_FAILED as _ {
                    // rewrite only if the original call moves the address
                    if mremap.flags() & nix::libc::MREMAP_MAYMOVE as usize != 0 {
                        let addr_raw = mremap.addr().map(|a| a.as_raw()).unwrap_or(0);

                        if addr_raw == saved_syscall.ret_val as _ {
                            mremap = mremap
                                .with_flags(mremap.flags() & !nix::libc::MREMAP_MAYMOVE as usize);
                        } else {
                            mremap = mremap
                                .with_new_addr(AddrMut::from_ptr(saved_syscall.ret_val as _))
                                .with_flags(mremap.flags() | nix::libc::MREMAP_FIXED as usize);
                        }
                    }

                    let (new_sysno, new_args) = mremap.into_parts();
                    active_segment
                        .checker
                        .process()
                        .unwrap()
                        .modify_registers_with(|regs| {
                            regs.with_sysno(new_sysno).with_syscall_args(new_args)
                        })?;
                }

                Ok(StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior)
            }
            _ => Ok(StandardSyscallEntryCheckerHandlerExitAction::NextHandler),
        }
    }

    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        let main = context.process();
        match saved_incomplete_syscall.syscall {
            Syscall::Mmap(_) | Syscall::Mremap(_) => {
                // restore registers as if we haven't modified mmap/mremap flags
                main.modify_registers_with(|regs| {
                    regs.with_syscall_args(saved_incomplete_syscall.syscall.into_parts().1)
                })?;

                Ok(SyscallHandlerExitAction::ContinueInferior)
            }
            Syscall::Mprotect(mprotect) => {
                if !mprotect.protection().contains(ProtFlags::PROT_WRITE) && ret_val == 0 {
                    let addr = mprotect.addr().map_or(0, |a| a.as_raw());
                    let len = mprotect.len();

                    self.extra_writable_ranges.lock().insert(addr..addr + len);
                }

                Ok(SyscallHandlerExitAction::NextHandler)
            }
            _ => Ok(SyscallHandlerExitAction::NextHandler),
        }
    }

    fn handle_standard_syscall_exit_checker(
        &self,
        _ret_val: isize,
        saved_syscall: &SavedSyscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        match saved_syscall.syscall {
            Syscall::Mmap(_) | Syscall::Mremap(_) => {
                // restore registers as if we haven't modified mmap/mremap flags
                context.process().modify_registers_with(|regs| {
                    regs.with_syscall_args(saved_syscall.syscall.into_parts().1)
                })?;

                Ok(SyscallHandlerExitAction::ContinueInferior)
            }
            _ => Ok(SyscallHandlerExitAction::NextHandler),
        }
    }
}

impl ExtraWritableRangesProvider for MmapHandler {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]> {
        let m = self.extra_writable_ranges.lock();

        m.iter().cloned().collect::<Box<_>>()
    }
}

impl Module for MmapHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_extra_writable_ranges_provider(self);
    }
}
