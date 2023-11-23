use log::{error, info};
use reverie_syscalls::{Addr, AddrMut, MapFlags, Syscall, SyscallInfo};

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::{Error, EventFlags, Result},
    saved_syscall::{
        SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedSyscall, SyscallExitAction,
    },
    segments::Segment,
};

use super::{
    HandlerContext, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler, SyscallHandlerExitAction,
};

pub struct MmapHandler {}

impl MmapHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for MmapHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        let syscall = *syscall;
        let main = &context.check_coord.main;

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

                        return Ok(
                            StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                                SavedIncompleteSyscall {
                                    syscall,
                                    kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                                    exit_action: SyscallExitAction::Checkpoint,
                                },
                            ),
                        );
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
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        let syscall = *syscall;
        let _main = &context.check_coord.main;

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
                        .syscall_log
                        .front()
                        .ok_or(Error::UnexpectedSyscall(EventFlags::IS_EXCESS))?;

                    if saved_syscall.syscall != syscall {
                        error!("Mmap syscall mismatch");
                        return Err(Error::UnexpectedSyscall(EventFlags::IS_INCORRECT));
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
                                .checker()
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
                    .syscall_log
                    .front()
                    .ok_or(Error::UnexpectedSyscall(EventFlags::IS_EXCESS))?;

                if saved_syscall.syscall != syscall {
                    info!("Mremap syscall mismatch");
                    return Err(Error::UnexpectedSyscall(EventFlags::IS_INCORRECT));
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
                        .checker()
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
        _ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        _active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        match saved_incomplete_syscall.syscall {
            Syscall::Mmap(_) | Syscall::Mremap(_) => {
                // restore registers as if we haven't modified mmap/mremap flags
                context.check_coord.main.modify_registers_with(|regs| {
                    regs.with_syscall_args(saved_incomplete_syscall.syscall.into_parts().1)
                })?;

                Ok(SyscallHandlerExitAction::ContinueInferior)
            }
            _ => Ok(SyscallHandlerExitAction::NextHandler),
        }
    }

    fn handle_standard_syscall_exit_checker(
        &self,
        _ret_val: isize,
        saved_syscall: &SavedSyscall,
        active_segment: &mut Segment,
        _context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        match saved_syscall.syscall {
            Syscall::Mmap(_) | Syscall::Mremap(_) => {
                // restore registers as if we haven't modified mmap/mremap flags
                active_segment
                    .checker()
                    .unwrap()
                    .modify_registers_with(|regs| {
                        regs.with_syscall_args(saved_syscall.syscall.into_parts().1)
                    })?;

                Ok(SyscallHandlerExitAction::ContinueInferior)
            }
            _ => Ok(SyscallHandlerExitAction::NextHandler),
        }
    }
}

impl<'a> Installable<'a> for MmapHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
    }
}
