use std::arch::x86_64::{CpuidResult, __cpuid_count};

use log::info;
use nix::sys::signal::Signal;
use reverie_syscalls::{Addr, MemoryAccess, Syscall};
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, EventFlags, Result},
    process::{Process, ProcessLifetimeHook, ProcessLifetimeHookContext},
    segments::SavedTrapEvent,
    syscall_handlers::{
        is_execve_ok, HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction,
    },
};

use super::{SignalHandler, SignalHandlerExitAction};

pub struct CpuidHandler;

impl CpuidHandler {
    pub fn new() -> Self {
        Self {}
    }

    fn enable_cpuid_faulting(process: &Process) -> Result<()> {
        let ret = process.syscall_direct(
            Sysno::arch_prctl,
            syscall_args!(0x1012 /* ARCH_SET_CPUID */, 0),
            true,
            false,
            true,
        )?;
        assert_eq!(ret, 0);
        info!("Cpuid init done");

        Ok(())
    }
}

impl SignalHandler for CpuidHandler {
    fn handle_signal<'s, 'p, 'segs, 'disp, 'scope, 'env, 'modules>(
        &'s self,
        signal: Signal,
        context: &HandlerContext<'p, 'segs, 'disp, 'scope, 'env, 'modules>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
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
                    .segments
                    .lookup_segment_with::<Result<CpuidResult>>(
                        process.pid,
                        |mut segment, is_main| {
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
                                    .ok_or(Error::UnexpectedTrap(EventFlags::IS_EXCESS))?;

                                if let SavedTrapEvent::Cpuid(leaf, subleaf, cpuid) = event {
                                    assert_eq!(regs.cpuid_leaf_subleaf(), (leaf, subleaf));
                                    Ok(cpuid)
                                } else {
                                    Err(Error::UnexpectedTrap(EventFlags::IS_INCORRECT))
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
        if is_execve_ok(syscall, ret_val) {
            // arch_prctl cpuid is cleared after every execve
            Self::enable_cpuid_faulting(context.process)?;
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for CpuidHandler {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Self::enable_cpuid_faulting(context.process)
    }
}

impl Module for CpuidHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_signal_handler(self);
        subs.install_standard_syscall_handler(self);
        subs.install_process_lifetime_hook(self);
    }
}
