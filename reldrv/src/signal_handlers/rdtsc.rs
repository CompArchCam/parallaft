use std::{
    arch::x86_64::{__rdtscp, _rdtsc},
    mem::MaybeUninit,
    sync::atomic::{AtomicBool, Ordering},
};

use log::info;
use nix::{libc, sys::signal::Signal};
use reverie_syscalls::{Addr, MemoryAccess};
use syscalls::{syscall_args, SyscallArgs, Sysno};

use crate::{
    dispatcher::{Dispatcher, Installable},
    segments::SavedTrapEvent,
    syscall_handlers::{CustomSyscallHandler, HandlerContext, SyscallHandlerExitAction},
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
    fn handle_signal(&self, signal: Signal, context: &HandlerContext) -> SignalHandlerExitAction {
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
            let regs = process.read_registers();
            let instr: u64 = process
                .read_value(Addr::from_raw(regs.inner.rip as _).unwrap())
                .unwrap();

            if instr & 0xffff == 0x310f {
                info!("[PID {: >8}] Trap: Rdtsc", process.pid);

                // rdtsc
                let tsc = context
                    .check_coord
                    .segments
                    .get_active_segment_with(process.pid, |segment, is_main| {
                        if is_main {
                            let tsc = get_rdtsc();
                            // add to the log
                            segment.trap_event_log.push_back(SavedTrapEvent::Rdtsc(tsc));
                            tsc
                        } else {
                            // replay from the log
                            let event = segment.trap_event_log.pop_front().unwrap();
                            if let SavedTrapEvent::Rdtsc(tsc) = event {
                                tsc
                            } else {
                                panic!("Unexpected trap event");
                            }
                        }
                    })
                    .unwrap_or_else(get_rdtsc);

                process.write_registers(regs.with_tsc(tsc).with_offsetted_rip(2));

                return SignalHandlerExitAction::SuppressSignalAndContinueInferior;
            } else if instr & 0xffffff == 0xf9010f {
                info!("[PID {: >8}] Trap: Rdtscp", process.pid);

                // rdtscp
                let (tsc, aux) = context
                    .check_coord
                    .segments
                    .get_active_segment_with(process.pid, |segment, is_main| {
                        if is_main {
                            let (tsc, aux) = get_rdtscp();

                            segment
                                .trap_event_log
                                .push_back(SavedTrapEvent::Rdtscp(tsc, aux));

                            (tsc, aux)
                        } else {
                            // replay from the log
                            let event = segment.trap_event_log.pop_front().unwrap();
                            if let SavedTrapEvent::Rdtscp(tsc, aux) = event {
                                (tsc, aux)
                            } else {
                                panic!("Unexpected trap event");
                            }
                        }
                    })
                    .unwrap_or_else(get_rdtscp);

                process.write_registers(regs.with_tscp(tsc, aux).with_offsetted_rip(3));

                return SignalHandlerExitAction::SuppressSignalAndContinueInferior;
            }
        }

        SignalHandlerExitAction::NextHandler
    }
}

impl CustomSyscallHandler for RdtscHandler {
    fn handle_custom_syscall_entry(
        &self,
        _sysno: usize,
        _args: SyscallArgs,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        if context.check_coord.main.pid == context.process.pid
            && self
                .init_done
                .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            let ret = context.process.syscall_direct(
                Sysno::prctl,
                syscall_args!(libc::PR_SET_TSC as _, libc::PR_TSC_SIGSEGV as _),
                true,
                false,
            );
            assert_eq!(ret, 0);
            info!("Rdtsc init done");
        };

        SyscallHandlerExitAction::NextHandler
    }
}

impl<'a> Installable<'a> for RdtscHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_signal_handler(self);
        dispatcher.install_custom_syscall_handler(self);
    }
}
