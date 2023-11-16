use std::arch::x86_64::{CpuidResult, __cpuid_count};

use log::info;
use nix::sys::signal::Signal;
use reverie_syscalls::{Addr, MemoryAccess, Syscall};
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::{Error, Result},
    segments::SavedTrapEvent,
    syscall_handlers::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction},
};

use super::{SignalHandler, SignalHandlerExitAction};

pub struct CpuidHandler;

impl CpuidHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl SignalHandler for CpuidHandler {
    fn handle_signal<'s, 'p, 'c, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: &HandlerContext<'p, 'c, 'scope, 'env>,
    ) -> Result<SignalHandlerExitAction>
    where
        'c: 'scope,
    {
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
        ret_val: isize,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) && ret_val == 0 {
            // arch_prctl cpuid is cleared after every execve
            let ret = context.process.syscall_direct(
                Sysno::arch_prctl,
                syscall_args!(0x1012 /* ARCH_SET_CPUID */, 0),
                true,
                false,
                true,
            )?;
            assert_eq!(ret, 0);
            info!("Cpuid init done");
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> Installable<'a> for CpuidHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_signal_handler(self);
        dispatcher.install_standard_syscall_handler(self);
    }
}
