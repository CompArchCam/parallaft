use std::{
    arch::x86_64::{CpuidResult, __cpuid_count},
    sync::atomic::{AtomicBool, Ordering},
};

use log::info;
use nix::sys::signal::Signal;
use reverie_syscalls::{Addr, MemoryAccess, Syscall};
use syscalls::{syscall_args, SyscallArgs, Sysno};

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::{Error, Result},
    segments::SavedTrapEvent,
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction,
    },
};

use super::{SignalHandler, SignalHandlerExitAction};

pub struct CpuidHandler {
    init_done: AtomicBool,
}

impl CpuidHandler {
    pub fn new() -> Self {
        Self {
            init_done: AtomicBool::new(false),
        }
    }
}

impl SignalHandler for CpuidHandler {
    fn handle_signal(
        &self,
        signal: Signal,
        context: &HandlerContext,
    ) -> Result<SignalHandlerExitAction> {
        let process = context.process;

        if signal == Signal::SIGSEGV {
            let regs = process.read_registers()?;
            let instr: u64 = process.read_value(Addr::from_raw(regs.rip as _).unwrap())?;

            let get_cpuid = || {
                let (leaf, subleaf) = regs.cpuid_leaf_subleaf();
                unsafe { __cpuid_count(leaf, subleaf) }
            };

            if instr & 0xffff == 0xa20f {
                info!("[PID {: >8}] Trap: Cpuid", process.pid);

                // cpuid
                let cpuid = context
                    .check_coord
                    .segments
                    .get_active_segment_with::<Result<CpuidResult>>(
                        process.pid,
                        |segment, is_main| {
                            if is_main {
                                let (leaf, subleaf) = regs.cpuid_leaf_subleaf();
                                let cpuid = get_cpuid();

                                // add to the log
                                segment
                                    .trap_event_log
                                    .push_back(SavedTrapEvent::Cpuid(leaf, subleaf, cpuid));

                                Ok(cpuid)
                            } else {
                                // replay from the log
                                let event = segment
                                    .trap_event_log
                                    .pop_front()
                                    .ok_or(Error::UnexpectedTrap)?;

                                if let SavedTrapEvent::Cpuid(leaf, subleaf, cpuid) = event {
                                    assert_eq!(regs.cpuid_leaf_subleaf(), (leaf, subleaf));
                                    Ok(cpuid)
                                } else {
                                    panic!("Unexpected trap event");
                                }
                            }
                        },
                    )
                    .unwrap_or_else(|| Ok(get_cpuid()))?;

                process.write_registers(regs.with_cpuid_result(cpuid).with_offsetted_rip(2))?;

                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl StandardSyscallHandler for CpuidHandler {
    fn handle_standard_syscall_exit(
        &self,
        _ret_val: isize,
        syscall: &Syscall,
        _context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) {
            // arch_prctl cpuid is cleared after every execve
            self.init_done.store(false, Ordering::SeqCst);
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl CustomSyscallHandler for CpuidHandler {
    fn handle_custom_syscall_entry(
        &self,
        _sysno: usize,
        _args: SyscallArgs,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if context.check_coord.main.pid == context.process.pid
            && self
                .init_done
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let ret = context.process.syscall_direct(
                Sysno::arch_prctl,
                syscall_args!(0x1012 /* ARCH_SET_CPUID */, 0),
                true,
                false,
            )?;
            assert_eq!(ret, 0);
            info!("Cpuid init done");
        };

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> Installable<'a> for CpuidHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_signal_handler(self);
        dispatcher.install_custom_syscall_handler(self);
        dispatcher.install_standard_syscall_handler(self);
    }
}
