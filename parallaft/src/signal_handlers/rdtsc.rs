use std::{
    arch::x86_64::{__rdtscp, _rdtsc},
    mem::MaybeUninit,
};

use log::info;
use nix::{libc, sys::signal::Signal};

use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{memory::instructions, registers::RegisterAccess, state::Stopped},
    signal_handlers::handle_nondeterministic_instruction,
    types::{process_id::Main, segment_record::saved_trap_event::SavedTrapEvent},
};

pub struct RdtscHandler;

impl Default for RdtscHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RdtscHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl SignalHandler for RdtscHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        mut context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGSEGV {
            let regs = context.process().read_registers()?;

            if context.process().instr_eq(regs.ip(), instructions::RDTSC) {
                info!("{} Trap: Rdtsc", context.child);

                let tsc = handle_nondeterministic_instruction(
                    &context.child,
                    || unsafe { _rdtsc() },
                    SavedTrapEvent::Rdtsc,
                    |event| {
                        if let SavedTrapEvent::Rdtsc(tsc) = event {
                            Ok(tsc)
                        } else {
                            Err(Error::UnexpectedEvent(
                                UnexpectedEventReason::IncorrectValue,
                            ))
                        }
                    },
                )?;

                context.process_mut().write_registers(
                    regs.with_tsc(tsc.value)
                        .with_offsetted_ip(instructions::RDTSC.length() as _),
                )?;

                return Ok(tsc.signal_handler_exit_action());
            } else if context.process().instr_eq(regs.ip(), instructions::RDTSCP) {
                info!("{} Trap: Rdtscp", context.child);

                let tscp = handle_nondeterministic_instruction(
                    &context.child,
                    || {
                        let mut aux = MaybeUninit::uninit();
                        let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
                        let aux = unsafe { aux.assume_init() };
                        (tsc, aux)
                    },
                    |tscp| SavedTrapEvent::Rdtscp(tscp.0, tscp.1),
                    |event| {
                        if let SavedTrapEvent::Rdtscp(tsc, aux) = event {
                            Ok((tsc, aux))
                        } else {
                            Err(Error::UnexpectedEvent(
                                UnexpectedEventReason::IncorrectValue,
                            ))
                        }
                    },
                )?;

                context.process_mut().write_registers(
                    regs.with_tscp(tscp.value.0, tscp.value.1)
                        .with_offsetted_ip(instructions::RDTSCP.length() as _),
                )?;

                return Ok(tscp.signal_handler_exit_action());
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for RdtscHandler {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        let ret = main.try_map_process_inplace(|p| {
            p.syscall_direct(
                Sysno::prctl,
                syscall_args!(libc::PR_SET_TSC as _, libc::PR_TSC_SIGSEGV as _),
                false,
                false,
                true,
            )
        })?;

        assert_eq!(ret, 0);
        info!("Rdtsc init done");
        Ok(())
    }
}

impl Module for RdtscHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_signal_handler(self);
        subs.install_process_lifetime_hook(self);
    }
}
