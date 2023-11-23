use std::{
    arch::x86_64::{__rdtscp, _rdtsc},
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};

use log::info;
use nix::{libc, sys::signal::Signal};
use reverie_syscalls::{Addr, MemoryAccess, Syscall};
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::{Error, EventFlags, Result},
    segments::SavedTrapEvent,
    syscall_handlers::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction},
};

use super::{SignalHandler, SignalHandlerExitAction};

pub struct RdtscHandler {
    init_done: AtomicBool,
}

impl RdtscHandler {
    pub fn new() -> Self {
        Self {
            init_done: AtomicBool::new(false),
        }
    }
}

impl SignalHandler for RdtscHandler {
    fn handle_signal<'s, 'p, 'segs, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: &HandlerContext<'p, 'segs, 'disp, 'scope, 'env>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        let process = context.process;

        let get_rdtsc = || unsafe { _rdtsc() };

        let get_rdtscp = || {
            let mut aux = MaybeUninit::uninit();
            // add to the log
            let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
            let aux = unsafe { aux.assume_init() };
            (tsc, aux)
        };

        if signal == Signal::SIGSEGV {
            let regs = process.read_registers()?;
            let instr: u64 = process.read_value(Addr::from_raw(regs.rip as _).unwrap())?;

            if instr & 0xffff == 0x310f {
                info!("[PID {: >8}] Trap: Rdtsc", process.pid);

                // rdtsc
                let tsc = context
                    .segments
                    .lookup_segment_with::<Result<u64>>(process.pid, |mut segment, is_main| {
                        if is_main {
                            let tsc = get_rdtsc();
                            // add to the log
                            segment.trap_event_log.push_back(SavedTrapEvent::Rdtsc(tsc));
                            Ok(tsc)
                        } else {
                            // replay from the log
                            let event = segment
                                .trap_event_log
                                .pop_front()
                                .ok_or(Error::UnexpectedTrap(EventFlags::IS_EXCESS))?;

                            if let SavedTrapEvent::Rdtsc(tsc) = event {
                                Ok(tsc)
                            } else {
                                Err(Error::UnexpectedTrap(EventFlags::IS_INCORRECT))
                            }
                        }
                    })
                    .unwrap_or_else(|| Ok(get_rdtsc()))?;

                process.write_registers(regs.with_tsc(tsc).with_offsetted_rip(2))?;

                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior);
            } else if instr & 0xffffff == 0xf9010f {
                info!("[PID {: >8}] Trap: Rdtscp", process.pid);

                // rdtscp
                let (tsc, aux) = context
                    .segments
                    .lookup_segment_with::<Result<(u64, u32)>>(
                        process.pid,
                        |mut segment, is_main| {
                            if is_main {
                                let (tsc, aux) = get_rdtscp();

                                segment
                                    .trap_event_log
                                    .push_back(SavedTrapEvent::Rdtscp(tsc, aux));

                                Ok((tsc, aux))
                            } else {
                                // replay from the log
                                let event = segment
                                    .trap_event_log
                                    .pop_front()
                                    .ok_or(Error::UnexpectedTrap(EventFlags::IS_EXCESS))?;

                                if let SavedTrapEvent::Rdtscp(tsc, aux) = event {
                                    Ok((tsc, aux))
                                } else {
                                    Err(Error::UnexpectedTrap(EventFlags::IS_INCORRECT))
                                }
                            }
                        },
                    )
                    .unwrap_or_else(|| Ok(get_rdtscp()))?;

                process.write_registers(regs.with_tscp(tsc, aux).with_offsetted_rip(3))?;

                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl StandardSyscallHandler for RdtscHandler {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &reverie_syscalls::Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_))
            && ret_val == 0
            && self
                .init_done
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let ret = context.process.syscall_direct(
                Sysno::prctl,
                syscall_args!(libc::PR_SET_TSC as _, libc::PR_TSC_SIGSEGV as _),
                false,
                false,
                true,
            )?;
            assert_eq!(ret, 0);
            info!("Rdtsc init done");
        };

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> Installable<'a> for RdtscHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_signal_handler(self);
        dispatcher.install_standard_syscall_handler(self);
    }
}
