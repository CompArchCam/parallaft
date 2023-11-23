//! PMU-interrupt-based segmentation

use std::collections::HashMap;

use log::{debug, info};

use nix::{
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use parking_lot::Mutex;
use perf_event::{Counter, SampleSkid};
use reverie_syscalls::Syscall;

use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Dispatcher, Installable},
    error::Result,
    segments::{Segment, SegmentEventHandler},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction},
};

use super::ScheduleCheckpoint;

const MAX_SKID: u64 = 256;
const PERF_EVENT_RAW_BRANCH_RETIRED: u64 = 0xbbc4; // branches retired excluding far branches

struct SegmentInfo {
    condbrs: u64,
    ip: u64,
    state: Option<CheckerState>,
}

enum CheckerState {
    CountingBranches {
        condbr_irq: Counter,
        condbr_counter: Counter,
    },
    Stepping {
        condbr_counter: Counter,
        breakpoint: Counter,
    },
    Done,
}

pub struct PmuSegmentor {
    period: u64,
    segment_info_map: Mutex<HashMap<Pid, SegmentInfo>>,
    main_state: Mutex<Option<MainState>>,
}

#[derive(Debug)]
enum MainState {
    Idle,
    CountingInstructions {
        instr_irq: Counter,
        condbr_counter: Counter,
    },
    CountingBranches {
        condbr_irq: Counter,
        condbr_counter: Counter, // required because the counter that generates interrupt may be stale
    },
}

impl PmuSegmentor {
    pub fn new(period: u64) -> Self {
        Self {
            period,
            main_state: Mutex::new(Some(MainState::Idle)),
            segment_info_map: Mutex::new(HashMap::new()),
        }
    }

    fn instr_counter(&self, pid: Pid, period: u64) -> Counter {
        perf_event::Builder::new(perf_event::events::Hardware::INSTRUCTIONS)
            .observe_pid(pid.as_raw() as _)
            .wakeup_events(1)
            .sample_period(period)
            .sigtrap(true)
            .remove_on_exec(true)
            .enabled(true)
            .pinned(true)
            .build()
            .expect("Failed to initialise perf counter. Your hardware may not support it.")
    }

    fn condbr_counter(&self, pid: Pid) -> Counter {
        perf_event::Builder::new(perf_event::events::Raw::new(PERF_EVENT_RAW_BRANCH_RETIRED))
            .observe_pid(pid.as_raw() as _)
            .enabled(true)
            .pinned(true)
            .build()
            .unwrap()
    }

    fn condbr_irq(&self, pid: Pid, period: u64) -> Counter {
        perf_event::Builder::new(perf_event::events::Raw::new(PERF_EVENT_RAW_BRANCH_RETIRED))
            .observe_pid(pid.as_raw() as _)
            .wakeup_events(1)
            .sample_period(period)
            .precise_ip(SampleSkid::RequireZero)
            .sigtrap(true)
            .remove_on_exec(true)
            .enabled(true)
            .pinned(true)
            .build()
            .expect("Failed to initialise perf counter. Your hardware may not support it.")
    }

    fn breakpoint(&self, pid: Pid, address: u64) -> Counter {
        perf_event::Builder::new(perf_event::events::Breakpoint::execute(address))
            .sample_period(1)
            .observe_pid(pid.as_raw() as _)
            .sigtrap(true)
            .remove_on_exec(true)
            .enabled(true)
            .pinned(true)
            .build()
            .unwrap()
    }
}

impl SegmentEventHandler for PmuSegmentor {
    fn handle_segment_checked(&self, segment: &Segment) -> Result<()> {
        let mut counters = self.segment_info_map.lock();
        counters.remove(&segment.checker().unwrap().pid);
        Ok(())
    }

    fn handle_checkpoint_created_pre(&self, _main_pid: Pid) -> Result<()> {
        let mut main_state = self.main_state.lock();

        match main_state.as_mut().unwrap() {
            MainState::CountingInstructions {
                ref mut condbr_counter,
                ref mut instr_irq,
            } => {
                condbr_counter.reset().unwrap();
                condbr_counter.enable().unwrap();
                instr_irq.reset().unwrap();
                instr_irq.enable().unwrap();
            }
            _ => panic!("Invalid main state: {:?}", main_state.as_mut()),
        }

        Ok(())
    }
}

impl StandardSyscallHandler for PmuSegmentor {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        match syscall {
            Syscall::Execve(_) | Syscall::Execveat(_) if ret_val == 0 => {
                assert_eq!(context.process.pid, context.check_coord.main.pid);

                *self.main_state.lock() = Some(MainState::CountingInstructions {
                    instr_irq: self.instr_counter(context.process.pid, self.period),
                    condbr_counter: self.condbr_counter(context.process.pid),
                });

                info!("PMU-interrupt-based segmentation enabled");
            }
            _ => (),
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for PmuSegmentor {
    fn handle_signal<'s, 'p, 'segs, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: &HandlerContext<'p, 'segs, 'disp, 'scope, 'env>,
    ) -> Result<crate::signal_handlers::SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGTRAP && ptrace::getsiginfo(context.process.pid)?.si_code == 0x6
        /* TRAP_PERF */
        {
            let ip = context.process.read_registers().unwrap().rip;

            let mut take_checkpoint = false;

            debug!(
                "[PID {: >8}] Trap: Perf @ IP = {:p}",
                context.process.pid, ip as *const u8
            );

            if context.process.pid == context.check_coord.main.pid {
                let mut state = self.main_state.lock();

                let next_state = match state.take().unwrap() {
                    MainState::CountingInstructions {
                        mut instr_irq,
                        condbr_counter,
                    } => {
                        instr_irq.disable().unwrap();
                        MainState::CountingBranches {
                            condbr_irq: self.condbr_irq(context.process.pid, 4096),
                            condbr_counter,
                        }
                    }
                    MainState::CountingBranches {
                        mut condbr_irq,
                        mut condbr_counter,
                    } => {
                        condbr_irq.disable().unwrap();
                        condbr_counter.disable().unwrap();
                        let condbrs = condbr_counter.read().unwrap();
                        debug!("Main conditional branches executed = {}", condbrs);

                        if let Some(segment) = context.segments.last_segment() {
                            let segment = segment.lock();
                            let checker_pid = segment.checker().unwrap().pid;

                            let mut segment_info_map = self.segment_info_map.lock();
                            segment_info_map.insert(
                                checker_pid,
                                SegmentInfo {
                                    condbrs,
                                    ip,
                                    state: Some(CheckerState::CountingBranches {
                                        condbr_irq: self
                                            .condbr_irq(checker_pid, condbrs - MAX_SKID),
                                        condbr_counter: self.condbr_counter(checker_pid),
                                    }),
                                },
                            );
                        };

                        take_checkpoint = true;

                        MainState::CountingInstructions {
                            instr_irq: self.instr_counter(context.process.pid, self.period),
                            condbr_counter: self.condbr_counter(context.process.pid),
                        }
                    }
                    MainState::Idle => panic!("Invalid state"),
                };

                *state = Some(next_state);
            } else {
                let mut segment_info_map = self.segment_info_map.lock();
                let segment_info = segment_info_map.get_mut(&context.process.pid).unwrap();

                let next_state = match segment_info.state.take().unwrap() {
                    CheckerState::CountingBranches {
                        mut condbr_irq,
                        mut condbr_counter,
                    } => {
                        condbr_irq.disable().unwrap();
                        let condbrs = condbr_counter.read().unwrap();
                        let diff = segment_info.condbrs.wrapping_sub(condbrs) as i64;

                        debug!(
                            "Checker conditional branches executed = {} (diff = {})",
                            condbrs, diff
                        );

                        if diff > 0 {
                            CheckerState::Stepping {
                                condbr_counter,
                                breakpoint: self.breakpoint(context.process.pid, segment_info.ip),
                            }
                        } else if diff == 0 {
                            CheckerState::Done
                        } else {
                            panic!("Skid detected");
                        }
                    }
                    CheckerState::Stepping {
                        mut condbr_counter,
                        breakpoint,
                    } => {
                        debug!("Breakpoint hit");

                        let condbrs = condbr_counter.read().unwrap();
                        let diff = segment_info.condbrs.wrapping_sub(condbrs) as i64;
                        debug!(
                            "Checker conditional branches executed = {} (diff = {})",
                            condbrs, diff
                        );

                        if diff > 0 {
                            CheckerState::Stepping {
                                condbr_counter,
                                breakpoint,
                            }
                        } else if diff == 0 {
                            context
                                .process
                                .modify_registers_with(|r| r.with_resume_flag_cleared())
                                .unwrap();
                            CheckerState::Done
                        } else {
                            panic!("Unexpected breakpoint skid");
                        }
                    }
                    CheckerState::Done => panic!("Invalid state"),
                };

                let next_state = segment_info.state.insert(next_state);

                if matches!(next_state, CheckerState::Done) {
                    take_checkpoint = true;
                }

                // TODO: error handling
            }

            if take_checkpoint {
                return Ok(SignalHandlerExitAction::Checkpoint);
            } else {
                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ScheduleCheckpoint for PmuSegmentor {
    fn schedule_checkpoint(&self, _check_coord: &CheckCoordinator) -> Result<()> {
        todo!()
    }
}

impl<'a> Installable<'a> for PmuSegmentor {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_segment_event_handler(self);
        dispatcher.install_standard_syscall_handler(self);
        dispatcher.install_signal_handler(self);
        dispatcher.install_schedule_checkpoint(self);
    }
}
