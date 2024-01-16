//! PMU-interrupt-based segmentation

use std::{collections::HashMap, io};

use lazy_static::lazy_static;
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
    dispatcher::{Module, Subscribers},
    error::Result,
    segments::{Segment, SegmentEventHandler, SegmentId},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction},
};

use super::ScheduleCheckpoint;

const INTEL_PERF_EVENT_BRANCH_RETIRED: u64 = 0xbbc4; // branches retired excluding far branches
const AMD_PERF_EVENT_EX_RET_BRN_FAR: u64 = 0xc6;
const AMD_PERF_EVENT_EX_RET_BRN: u64 = 0xc2;

#[derive(Debug)]
enum PmuType {
    // TODO: more precise model detection
    Amd,
    Intel,
    Unknown,
}

impl PmuType {
    fn detect() -> Self {
        let cpuid0 = unsafe { std::arch::x86_64::__cpuid(0) };
        let mut vendor = [0; 12];
        vendor[0..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

        let vendor = std::str::from_utf8(&vendor).unwrap_or("[INVALID]");

        match vendor {
            "AuthenticAMD" => Self::Amd,
            "GenuineIntel" => Self::Intel,
            _ => Self::Unknown,
        }
    }
}

lazy_static! {
    static ref PMU_TYPE: PmuType = {
        let t = PmuType::detect();
        info!("PMU type: {:?}", t);
        t
    };
    static ref MAX_SKID: u64 = {
        match *PMU_TYPE {
            PmuType::Amd => 2048,
            PmuType::Intel => 256,
            PmuType::Unknown => 0,
        }
    };
}

trait PmuCounter {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
    fn reset(&mut self) -> io::Result<()>;
    fn read(&mut self) -> io::Result<u64>;
}

struct PmuCounterSingle {
    counter: Counter,
}

impl PmuCounterSingle {
    pub fn new(counter: Counter) -> Self {
        Self { counter }
    }
}

impl PmuCounter for PmuCounterSingle {
    fn enable(&mut self) -> io::Result<()> {
        self.counter.enable()
    }

    fn disable(&mut self) -> io::Result<()> {
        self.counter.disable()
    }

    fn reset(&mut self) -> io::Result<()> {
        self.counter.reset()
    }

    fn read(&mut self) -> io::Result<u64> {
        self.counter.read()
    }
}

struct PmuCounterDiff {
    counter1: Box<dyn PmuCounter + Send>,
    counter2: Box<dyn PmuCounter + Send>,
}

impl PmuCounterDiff {
    pub fn new(counter1: Box<dyn PmuCounter + Send>, counter2: Box<dyn PmuCounter + Send>) -> Self {
        Self { counter1, counter2 }
    }
}

impl PmuCounter for PmuCounterDiff {
    fn enable(&mut self) -> io::Result<()> {
        self.counter1.enable()?;
        self.counter2.enable()?;
        Ok(())
    }

    fn disable(&mut self) -> io::Result<()> {
        self.counter1.disable()?;
        self.counter2.disable()?;
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        self.counter1.reset()?;
        self.counter2.reset()?;
        Ok(())
    }

    fn read(&mut self) -> io::Result<u64> {
        Ok(self.counter1.read()? - self.counter2.read()?)
    }
}

struct SegmentInfo {
    condbrs: u64,
    ip: u64,
    state: Option<CheckerState>,
}

enum CheckerState {
    CountingBranches {
        condbr_irq: Box<dyn PmuCounter + Send>,
        condbr_counter: Box<dyn PmuCounter + Send>,
    },
    Stepping {
        condbr_counter: Box<dyn PmuCounter + Send>,
        breakpoint: Counter,
    },
    Done,
}

pub struct PmuSegmentor {
    period: u64,
    segment_info_map: Mutex<HashMap<Pid, SegmentInfo>>,
    main_state: Mutex<Option<MainState>>,
    skip_instructions: Option<u64>,
}

enum MainState {
    New,
    SkippingInstructions {
        _instr_irq: Box<dyn PmuCounter + Send>,
    },
    CountingBranches {
        instr_irq: Box<dyn PmuCounter + Send>,
        condbr_counter: Box<dyn PmuCounter + Send>,
    },
}

impl PmuSegmentor {
    const SIGVAL_MAGIC: usize = 0xdeadbeef;

    pub fn new(period: u64, skip_instructions: Option<u64>) -> Self {
        Self {
            period,
            main_state: Mutex::new(Some(MainState::New)),
            segment_info_map: Mutex::new(HashMap::new()),
            skip_instructions,
        }
    }

    fn instr_counter(&self, pid: Pid, period: u64) -> Box<dyn PmuCounter + Send> {
        let counter = perf_event::Builder::new(perf_event::events::Hardware::INSTRUCTIONS)
            .observe_pid(pid.as_raw() as _)
            .wakeup_events(1)
            .sample_period(period)
            .sigtrap(true)
            .remove_on_exec(true)
            .enabled(true)
            .pinned(true)
            .build()
            .expect("Failed to initialise perf counter. Your hardware may not support it.");

        Box::new(PmuCounterSingle::new(counter))
    }

    fn condbr_counter(&self, pid: Pid) -> Box<dyn PmuCounter + Send> {
        match *PMU_TYPE {
            PmuType::Amd => {
                let counter1 = perf_event::Builder::new(perf_event::events::Raw::new(
                    AMD_PERF_EVENT_EX_RET_BRN,
                ))
                .observe_pid(pid.as_raw() as _)
                .enabled(true)
                .pinned(true)
                .build()
                .unwrap();

                let counter2 = perf_event::Builder::new(perf_event::events::Raw::new(
                    AMD_PERF_EVENT_EX_RET_BRN_FAR,
                ))
                .observe_pid(pid.as_raw() as _)
                .enabled(true)
                .pinned(true)
                .build()
                .unwrap();

                Box::new(PmuCounterDiff::new(
                    Box::new(PmuCounterSingle::new(counter1)),
                    Box::new(PmuCounterSingle::new(counter2)),
                ))
            }
            PmuType::Intel => {
                let counter = perf_event::Builder::new(perf_event::events::Raw::new(
                    INTEL_PERF_EVENT_BRANCH_RETIRED,
                ))
                .observe_pid(pid.as_raw() as _)
                .enabled(true)
                .pinned(true)
                .build()
                .unwrap();

                Box::new(PmuCounterSingle::new(counter))
            }
            PmuType::Unknown => panic!("Unsupported PMU"),
        }
    }

    fn condbr_irq(&self, pid: Pid, period: u64) -> Box<dyn PmuCounter + Send> {
        match *PMU_TYPE {
            PmuType::Amd => {
                let counter1 = perf_event::Builder::new(perf_event::events::Raw::new(
                    AMD_PERF_EVENT_EX_RET_BRN,
                ))
                .observe_pid(pid.as_raw() as _)
                .wakeup_events(1)
                .sample_period(period)
                .sigtrap(true)
                .remove_on_exec(true)
                .enabled(true)
                .pinned(true)
                .build()
                .unwrap();

                let counter2 = perf_event::Builder::new(perf_event::events::Raw::new(
                    AMD_PERF_EVENT_EX_RET_BRN_FAR,
                ))
                .observe_pid(pid.as_raw() as _)
                .enabled(true)
                .pinned(true)
                .build()
                .unwrap();

                Box::new(PmuCounterDiff::new(
                    Box::new(PmuCounterSingle::new(counter1)),
                    Box::new(PmuCounterSingle::new(counter2)),
                ))
            }
            PmuType::Intel => {
                let counter = perf_event::Builder::new(perf_event::events::Raw::new(
                    INTEL_PERF_EVENT_BRANCH_RETIRED,
                ))
                .observe_pid(pid.as_raw() as _)
                .wakeup_events(1)
                .sample_period(period)
                .precise_ip(SampleSkid::RequireZero)
                .sigtrap(true)
                .remove_on_exec(true)
                .enabled(true)
                .pinned(true)
                .build()
                .expect("Failed to initialise perf counter. Your hardware may not support it.");

                Box::new(PmuCounterSingle::new(counter))
            }
            PmuType::Unknown => panic!("Unsupported PMU"),
        }
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

    fn handle_checkpoint_created_pre(
        &self,
        _main_pid: Pid,
        _last_segment_id: Option<SegmentId>,
    ) -> Result<()> {
        let mut main_state = self.main_state.lock();

        match main_state.as_mut().unwrap() {
            MainState::CountingBranches {
                ref mut condbr_counter,
                ref mut instr_irq,
            } => {
                condbr_counter.reset().unwrap();
                condbr_counter.enable().unwrap();
                instr_irq.reset().unwrap();
                instr_irq.enable().unwrap();
            }
            _ => panic!("Invalid main state"),
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

                match self.skip_instructions {
                    Some(instrs) => {
                        let mut main_state = self.main_state.lock();
                        *main_state = Some(MainState::SkippingInstructions {
                            _instr_irq: self.instr_counter(context.process.pid, instrs),
                        })
                    }
                    None => self.schedule_checkpoint(context.check_coord)?,
                }

                info!("PMU-interrupt-based segmentation enabled");
            }
            _ => (),
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for PmuSegmentor {
    fn handle_signal<'s, 'p, 'segs, 'disp, 'scope, 'env, 'modules>(
        &'s self,
        signal: Signal,
        context: &HandlerContext<'p, 'segs, 'disp, 'scope, 'env, 'modules>,
    ) -> Result<crate::signal_handlers::SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGTRAP {
            let siginfo = ptrace::getsiginfo(context.process.pid)?;
            if siginfo.si_code == 0x6
                || (siginfo.si_code == -1
                    && unsafe { siginfo.si_value().sival_ptr }
                        == Self::SIGVAL_MAGIC as *mut nix::libc::c_void)
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
                        MainState::SkippingInstructions { .. } | MainState::New => {
                            take_checkpoint = true;

                            MainState::CountingBranches {
                                instr_irq: self.instr_counter(context.process.pid, self.period),
                                condbr_counter: self.condbr_counter(context.process.pid),
                            }
                        }
                        MainState::CountingBranches {
                            mut instr_irq,
                            mut condbr_counter,
                        } => {
                            instr_irq.disable().unwrap();
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
                                                .condbr_irq(checker_pid, condbrs - *MAX_SKID),
                                            condbr_counter: self.condbr_counter(checker_pid),
                                        }),
                                    },
                                );
                            };

                            take_checkpoint = true;

                            context
                                .check_coord
                                .main
                                .modify_registers_with(|r| r.with_resume_flag_cleared())?;

                            MainState::CountingBranches {
                                instr_irq: self.instr_counter(context.process.pid, self.period),
                                condbr_counter: self.condbr_counter(context.process.pid),
                            }
                        }
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
                                    breakpoint: self
                                        .breakpoint(context.process.pid, segment_info.ip),
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
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct siginfo_t_inner {
    si_signo: nix::libc::c_int,
    si_errno: nix::libc::c_int,
    si_code: nix::libc::c_int,
    si_pid: nix::libc::c_int,
    si_uid: nix::libc::c_int,
    si_ptr: *mut nix::libc::c_void,
}

#[repr(C)]
union siginfo_t {
    si: siginfo_t_inner,
    si_pad: [nix::libc::c_int; 128 / core::mem::size_of::<nix::libc::c_int>()],
}

impl ScheduleCheckpoint for PmuSegmentor {
    fn schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()> {
        unsafe {
            nix::libc::syscall(
                nix::libc::SYS_rt_sigqueueinfo,
                check_coord.main.pid.as_raw(),
                nix::libc::SIGTRAP,
                &siginfo_t {
                    si: siginfo_t_inner {
                        si_signo: nix::libc::SIGTRAP,
                        si_errno: 0,
                        si_code: -1, /* SI_QUEUE */
                        si_pid: 0,
                        si_uid: 0,
                        si_ptr: Self::SIGVAL_MAGIC as *mut nix::libc::c_void,
                    },
                },
            )
        };

        Ok(())
    }
}

impl Module for PmuSegmentor {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_standard_syscall_handler(self);
        subs.install_signal_handler(self);
        subs.install_schedule_checkpoint(self);
    }
}
