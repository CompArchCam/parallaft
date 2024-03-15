//! PMU-interrupt-based segmentation

mod counter;
mod perf_typed_raw;
mod pmu_type;

use std::collections::HashMap;

use log::{debug, info};

use nix::{
    sys::{ptrace, signal::Signal},
    unistd::Pid,
};
use parking_lot::Mutex;
use perf_event::{events::Raw, Counter, SampleSkid};
use reverie_syscalls::Syscall;

use crate::{
    check_coord::{CheckCoordinator, ProcessIdentityRef, ProcessRole},
    dispatcher::{Module, Subscribers},
    error::Result,
    inferior_rtlib::ScheduleCheckpoint,
    process::{ProcessLifetimeHook, ProcessLifetimeHookContext},
    segments::{Segment, SegmentEventHandler, SegmentId},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction},
};

use self::{
    counter::{perf_counter, PmuCounter, PmuCounterDiff},
    perf_typed_raw::TypedRaw,
    pmu_type::PmuType,
};

struct SegmentInfo {
    branches: u64,
    ip: usize,
    state: Option<CheckerState>,
}

enum CheckerState {
    CountingBranches {
        branch_irq: Box<dyn PmuCounter + Send>,
        branch_counter: Box<dyn PmuCounter + Send>,
    },
    Stepping {
        branch_counter: Box<dyn PmuCounter + Send>,
        breakpoint: Counter,
    },
    Done,
}

pub struct PmuSegmentor {
    period: u64,
    segment_info_map: Mutex<HashMap<Pid, SegmentInfo>>,
    main_state: Mutex<Option<MainState>>,
    skip_instructions: Option<u64>,
    main_pmu_type: PmuType,
    checker_pmu_type: PmuType,
    is_test: bool,
}

enum MainState {
    New,
    SkippingInstructions {
        _instr_irq: Box<dyn PmuCounter + Send>,
    },
    CountingBranches {
        instr_irq: Box<dyn PmuCounter + Send>,
        branch_counter: Box<dyn PmuCounter + Send>,
    },
}

impl PmuSegmentor {
    const SIGVAL_MAGIC: usize = 0xdeadbeef;

    pub fn new(
        period: u64,
        skip_instructions: Option<u64>,
        main_cpu_set: &[usize],
        checker_cpu_set: &[usize],
        is_test: bool,
    ) -> Self {
        let main_pmu_type = PmuType::detect(*main_cpu_set.get(0).unwrap_or(&0));
        let checker_pmu_type = PmuType::detect(*checker_cpu_set.get(0).unwrap_or(&0));

        info!("Detected PMU type for main = {:?}", main_pmu_type);
        info!("Detected PMU type for checker = {:?}", checker_pmu_type);

        Self {
            period,
            main_state: Mutex::new(Some(MainState::New)),
            segment_info_map: Mutex::new(HashMap::new()),
            skip_instructions,
            main_pmu_type,
            checker_pmu_type,
            is_test,
        }
    }

    fn pmu_type_for(&self, role: ProcessRole) -> PmuType {
        match role {
            ProcessRole::Main => self.main_pmu_type,
            ProcessRole::Checker => self.checker_pmu_type,
        }
    }

    fn instr_counter(
        &self,
        role: ProcessRole,
        pid: Pid,
        period: u64,
    ) -> Box<dyn PmuCounter + Send> {
        match self.pmu_type_for(role) {
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelMont { in_hybrid: true } => perf_counter(
                TypedRaw::new(0x08 /* cpu_atom */, 0xc0 /* instructions */),
                pid,
                Some((period, SampleSkid::Arbitrary)),
            ),
            _ => perf_counter(
                perf_event::events::Hardware::INSTRUCTIONS,
                pid,
                Some((period, SampleSkid::Arbitrary)),
            ),
        }
    }

    fn branch_counter(
        &self,
        role: ProcessRole,
        pid: Pid,
        irq_period: Option<u64>,
    ) -> Box<dyn PmuCounter + Send> {
        match self.pmu_type_for(role) {
            #[cfg(target_arch = "x86_64")]
            PmuType::Amd => Box::new(PmuCounterDiff::new(
                perf_counter(
                    Raw::new(0xc2 /* ex_ret_brn */),
                    pid,
                    irq_period.map(|period| (period, SampleSkid::Arbitrary)),
                ),
                perf_counter(Raw::new(0xc6 /* ex_ret_brn_far */), pid, None),
            )),
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelLakeCove | PmuType::IntelOther => {
                Box::new(PmuCounterDiff::new(
                    perf_counter(
                        Raw::new(0x00c4 /* BR_INST_RETIRED.ALL_BRANCHES */),
                        pid,
                        irq_period.map(|period| (period, SampleSkid::RequireZero)),
                    ),
                    perf_counter(Raw::new(0x40c4 /* BR_INST_RETIRED.FAR_BRANCH */), pid, None),
                ))
            }
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelMont { in_hybrid } => {
                let perf_event_type = if in_hybrid {
                    0x08 /* cpu_atom */
                } else {
                    0x04 /* cpu */
                };

                Box::new(PmuCounterDiff::new(
                    perf_counter(
                        TypedRaw::new(
                            perf_event_type,
                            0x00c4, /* BR_INST_RETIRED.ALL_BRANCHES */
                        ),
                        pid,
                        irq_period.map(|period| (period, SampleSkid::RequireZero)),
                    ),
                    perf_counter(
                        TypedRaw::new(
                            perf_event_type,
                            0xbfc4, /* BR_INST_RETIRED.FAR_BRANCH */
                        ),
                        pid,
                        None,
                    ),
                ))
            }
            _ => panic!("Unsupported PMU"),
        }
    }

    fn breakpoint(&self, pid: Pid, address: usize) -> Counter {
        perf_event::Builder::new(perf_event::events::Breakpoint::execute(address as _))
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
                ref mut branch_counter,
                ref mut instr_irq,
            } => {
                branch_counter.reset().unwrap();
                branch_counter.enable().unwrap();
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
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        match syscall {
            Syscall::Execve(_) | Syscall::Execveat(_) if ret_val == 0 => {
                assert!(context.child.is_main());

                match self.skip_instructions {
                    Some(instrs) => {
                        let mut main_state = self.main_state.lock();
                        *main_state = Some(MainState::SkippingInstructions {
                            _instr_irq: self.instr_counter(
                                ProcessRole::Main,
                                context.process().pid,
                                instrs,
                            ),
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
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_>,
    ) -> Result<crate::signal_handlers::SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGTRAP {
            let siginfo = ptrace::getsiginfo(context.process().pid)?;
            if siginfo.si_code == 0x6
                || (siginfo.si_code == -1
                    && unsafe { siginfo.si_value().sival_ptr }
                        == Self::SIGVAL_MAGIC as *mut nix::libc::c_void)
            /* TRAP_PERF */
            {
                let ip = context.process().read_registers().unwrap().ip();

                let mut take_checkpoint = false;

                info!("{} Trap: Perf @ IP = {:p}", context.child, ip as *const u8);

                if let ProcessIdentityRef::Main(process) = context.child {
                    let mut state = self.main_state.lock();

                    let next_state = match state.take().unwrap() {
                        MainState::SkippingInstructions { .. } | MainState::New => {
                            take_checkpoint = true;

                            MainState::CountingBranches {
                                instr_irq: self.instr_counter(
                                    ProcessRole::Main,
                                    process.pid,
                                    self.period,
                                ),
                                branch_counter: self.branch_counter(
                                    ProcessRole::Main,
                                    process.pid,
                                    None,
                                ),
                            }
                        }
                        MainState::CountingBranches {
                            mut instr_irq,
                            mut branch_counter,
                        } => {
                            instr_irq.disable().unwrap();
                            branch_counter.disable().unwrap();
                            let branches = branch_counter.read().unwrap();
                            debug!("Main branches executed = {}", branches);

                            if let Some(segment) =
                                context.check_coord.segments.read().main_segment()
                            {
                                let segment = segment.read();
                                let checker_pid = segment.checker().unwrap().pid;

                                let mut segment_info_map = self.segment_info_map.lock();
                                segment_info_map.insert(
                                    checker_pid,
                                    SegmentInfo {
                                        branches,
                                        ip,
                                        state: Some(CheckerState::CountingBranches {
                                            branch_irq: self.branch_counter(
                                                ProcessRole::Checker,
                                                checker_pid,
                                                Some(branches - self.checker_pmu_type.max_skid()),
                                            ),
                                            branch_counter: self.branch_counter(
                                                ProcessRole::Checker,
                                                checker_pid,
                                                None,
                                            ),
                                        }),
                                    },
                                );
                            };

                            take_checkpoint = true;

                            #[cfg(target_arch = "x86_64")]
                            process.modify_registers_with(|r| r.with_resume_flag_cleared())?;

                            MainState::CountingBranches {
                                instr_irq: self.instr_counter(
                                    ProcessRole::Main,
                                    process.pid,
                                    self.period,
                                ),
                                branch_counter: self.branch_counter(
                                    ProcessRole::Main,
                                    process.pid,
                                    None,
                                ),
                            }
                        }
                    };

                    *state = Some(next_state);
                } else {
                    let mut segment_info_map = self.segment_info_map.lock();
                    let segment_info = segment_info_map.get_mut(&context.process().pid).unwrap();

                    let next_state = match segment_info.state.take().unwrap() {
                        CheckerState::CountingBranches {
                            mut branch_irq,
                            mut branch_counter,
                        } => {
                            branch_irq.disable().unwrap();
                            let branches = branch_counter.read().unwrap();
                            let diff = segment_info.branches.wrapping_sub(branches) as i64;

                            debug!("Checker branches executed = {} (diff = {})", branches, diff);

                            if diff > 0 {
                                CheckerState::Stepping {
                                    branch_counter,
                                    breakpoint: self
                                        .breakpoint(context.process().pid, segment_info.ip),
                                }
                            } else if diff == 0 {
                                CheckerState::Done
                            } else {
                                panic!("Skid detected");
                            }
                        }
                        CheckerState::Stepping {
                            mut branch_counter,
                            breakpoint,
                        } => {
                            debug!("Breakpoint hit");

                            let branches = branch_counter.read().unwrap();
                            let diff = segment_info.branches.wrapping_sub(branches) as i64;
                            debug!("Checker branches executed = {} (diff = {})", branches, diff);

                            if diff > 0 {
                                CheckerState::Stepping {
                                    branch_counter,
                                    breakpoint,
                                }
                            } else if diff == 0 {
                                #[cfg(target_arch = "x86_64")]
                                context
                                    .process()
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

impl ProcessLifetimeHook for PmuSegmentor {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        if self.is_test {
            self.schedule_checkpoint(context.check_coord)?;
        }
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
        subs.install_process_lifetime_hook(self);
    }
}
