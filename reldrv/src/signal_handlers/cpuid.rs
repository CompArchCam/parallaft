use std::arch::x86_64::__cpuid_count;

use log::info;
use nix::sys::signal::Signal;
use reverie_syscalls::Syscall;
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    process::{memory::instructions, Process, ProcessLifetimeHook, ProcessLifetimeHookContext},
    segments::SavedTrapEvent,
    signal_handlers::handle_nondeterministic_instruction,
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

        assert_eq!(ret, 0, "CPUID faulting is not supported on your machine");
        info!("Cpuid init done");

        Ok(())
    }
}

impl SignalHandler for CpuidHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGSEGV {
            let regs = context.process().read_registers()?;

            if context.process().instr_eq(regs.ip(), instructions::CPUID) {
                info!("{} Trap: Cpuid", context.child);

                let (leaf, subleaf) = regs.cpuid_leaf_subleaf();

                let cpuid = handle_nondeterministic_instruction(
                    context.child,
                    context.check_coord,
                    || unsafe { __cpuid_count(leaf, subleaf) },
                    |cpuid| SavedTrapEvent::Cpuid(leaf, subleaf, cpuid),
                    |event| {
                        if let SavedTrapEvent::Cpuid(leaf, subleaf, cpuid_saved) = event {
                            if regs.cpuid_leaf_subleaf() != (leaf, subleaf) {
                                return Err(Error::UnexpectedTrap(
                                    UnexpectedEventReason::IncorrectTypeOrArguments,
                                ));
                            }
                            Ok(cpuid_saved)
                        } else {
                            Err(Error::UnexpectedTrap(
                                UnexpectedEventReason::IncorrectTypeOrArguments,
                            ))
                        }
                    },
                )?;

                context.process().write_registers(
                    regs.with_cpuid_result(cpuid)
                        .with_offsetted_ip(instructions::CPUID.length() as _),
                )?;

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
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            // arch_prctl cpuid is cleared after every execve
            Self::enable_cpuid_faulting(context.process())?;
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
