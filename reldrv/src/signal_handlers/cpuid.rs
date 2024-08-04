use std::{arch::x86_64::__cpuid_count, collections::HashMap};

use log::{debug, info};
use nix::sys::signal::Signal;
use parking_lot::Mutex;
use reverie_syscalls::Syscall;
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::{memory::instructions, registers::RegisterAccess, Process},
    signal_handlers::handle_nondeterministic_instruction,
    syscall_handlers::is_execve_ok,
    types::segment_record::saved_trap_event::SavedTrapEvent,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum CpuidResultRegister {
    Eax,
    Ebx,
    Ecx,
    Edx,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct CpuidOverride {
    leaf: u32,
    subleaf: Option<u32>,
    register: CpuidResultRegister,
    mask: u32,
    value: u32,
}

impl CpuidOverride {
    pub const fn new(
        leaf: u32,
        subleaf: Option<u32>,
        register: CpuidResultRegister,
        mask: u32,
        value: u32,
    ) -> Self {
        Self {
            leaf,
            subleaf,
            register,
            mask,
            value,
        }
    }
}

pub mod overrides {
    use super::{CpuidOverride, CpuidResultRegister};

    pub const NO_RDRAND: [CpuidOverride; 1] = [CpuidOverride::new(
        1,
        None,
        CpuidResultRegister::Ecx,
        1 << 30,
        0,
    )];

    pub const NO_XSAVE: [CpuidOverride; 3] = [
        CpuidOverride::new(1, None, CpuidResultRegister::Ecx, 1 << 26, 0), // Disable xsave
        CpuidOverride::new(1, None, CpuidResultRegister::Ecx, 1 << 27, 0), // Disable osxsave
        CpuidOverride::new(0xd, Some(0), CpuidResultRegister::Ebx, !0, 0), // Clear max size of xsave save area
    ];
}

pub struct CpuidHandler {
    overrides: Mutex<Vec<CpuidOverride>>,
}

impl Default for CpuidHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl CpuidHandler {
    pub fn new() -> Self {
        Self {
            overrides: Mutex::new(Vec::new()),
        }
    }

    pub fn set_overrides(&self, overrides: Vec<CpuidOverride>) {
        *self.overrides.lock() = overrides;
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

    fn is_cpuid(sig: Signal, process: &Process) -> Result<bool> {
        if sig == Signal::SIGSEGV {
            let regs = process.read_registers()?;

            if process.instr_eq(regs.ip(), instructions::CPUID) {
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl SignalHandler for CpuidHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if !Self::is_cpuid(signal, context.process())? {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        info!("{} Trap: Cpuid", context.child);

        let regs = context.process().read_registers()?;
        let (leaf, subleaf) = regs.cpuid_leaf_subleaf();

        let cpuid = handle_nondeterministic_instruction(
            &context.child,
            || {
                // Apply overrides
                let mut overrides_map = HashMap::new();

                let ovs = self.overrides.lock();

                for o in ovs.iter() {
                    if o.leaf == leaf && (o.subleaf == Some(subleaf) || o.subleaf.is_none()) {
                        let (mask, value) =
                            overrides_map.entry(o.register).or_insert_with(|| (0, 0));
                        *mask |= o.mask;
                        *value = (*value & !o.mask) | (o.mask & o.value);
                    }
                }

                let mut result = unsafe { __cpuid_count(leaf, subleaf) };

                let old_result = result;

                let mut changed = false;

                for (reg, (mask, value)) in overrides_map.iter() {
                    let reg = match reg {
                        CpuidResultRegister::Eax => &mut result.eax,
                        CpuidResultRegister::Ebx => &mut result.ebx,
                        CpuidResultRegister::Ecx => &mut result.ecx,
                        CpuidResultRegister::Edx => &mut result.edx,
                    };
                    *reg = (*reg & !mask) | (mask & value);
                    changed = true;
                }

                if changed {
                    debug!(
                        "Cpuid override applied (leaf=0x{:x}, subleaf=0x{:x}): \n{:#?} -> {:#?}",
                        leaf, subleaf, old_result, result
                    );
                }

                result
            },
            |cpuid| SavedTrapEvent::Cpuid(leaf, subleaf, cpuid),
            |event| {
                if let SavedTrapEvent::Cpuid(leaf, subleaf, cpuid_saved) = event {
                    if regs.cpuid_leaf_subleaf() != (leaf, subleaf) {
                        return Err(Error::UnexpectedEvent(
                            UnexpectedEventReason::IncorrectTypeOrArguments,
                        ));
                    }
                    Ok(cpuid_saved)
                } else {
                    Err(Error::UnexpectedEvent(
                        UnexpectedEventReason::IncorrectTypeOrArguments,
                    ))
                }
            },
        )?;

        context.process().write_registers(
            regs.with_cpuid_result(cpuid.value)
                .with_offsetted_ip(instructions::CPUID.length() as _),
        )?;

        Ok(cpuid.signal_handler_exit_action())
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
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
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
