//! PMU-interrupt-based segmentation
pub mod exec_point;

use std::{
    collections::{HashMap, LinkedList},
    fmt::Debug,
    sync::{
        atomic::{AtomicU64, Ordering},
        Arc,
    },
};

use exec_point::BranchCounterBasedExecutionPoint;
use log::{debug, error, info};

use nix::sys::signal::Signal;
use parking_lot::Mutex;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        module_lifetime::ModuleLifetimeHook,
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContext,
    },
    signal_handlers::cpuid::{self, CpuidOverride},
    statistics::StatisticsProvider,
    statistics_list,
    types::{
        execution_point::ExecutionPoint,
        perf_counter::{
            linux::LinuxPerfCounter,
            pmu_type::{detect_pmu_type_cached, PmuType},
            BranchCounterType, PerfCounterCheckInterrupt, PerfCounterWithInterrupt,
        },
        process_id::{Checker, InferiorRefMut, Main},
        segment::SegmentId,
    },
};

use super::ExecutionPointProvider;

pub struct SegmentInfo {
    checker_branch_counter: Option<Box<dyn PerfCounterWithInterrupt + Send>>,
    active_exec_point: Option<(BranchCounterBasedExecutionPoint, ExecutionPointReplayState)>,
    upcoming_exec_points: LinkedList<BranchCounterBasedExecutionPoint>,
}

impl Debug for SegmentInfo {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SegmentInfo")
            .field("state", &self.active_exec_point)
            .field("upcoming_exec_points", &self.upcoming_exec_points)
            .finish()
    }
}

enum ExecutionPointReplayState {
    CountingBranches {
        branch_irq: Box<dyn PerfCounterWithInterrupt + Send>,
    },
    Stepping {
        breakpoint: Box<dyn PerfCounterCheckInterrupt + Send>,
    },
}

impl Debug for ExecutionPointReplayState {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::CountingBranches { .. } => write!(f, "CountingBranches"),
            Self::Stepping { .. } => write!(f, "Stepping"),
        }
    }
}

pub struct PerfCounterBasedExecutionPointProvider {
    segment_info_map: Mutex<HashMap<SegmentId, Arc<Mutex<SegmentInfo>>>>,
    main_branch_counter: Mutex<Option<Box<dyn PerfCounterWithInterrupt + Send>>>,
    main_pmu_type: PmuType,
    checker_pmu_type: PmuType,
    is_test: bool,
    checkpoint_count: AtomicU64,
    branch_counter_type: BranchCounterType,
}

impl PerfCounterBasedExecutionPointProvider {
    pub(self) const SIGVAL_CHECKER_PREPARE_EXEC_POINT: usize = 0xeb5aadf82a35bd9f;

    pub fn new(
        main_cpu_set: &[usize],
        checker_cpu_set: &[usize],
        branch_counter_type: BranchCounterType,
        is_test: bool,
    ) -> Self {
        let main_pmu_type = detect_pmu_type_cached(*main_cpu_set.first().unwrap_or(&0));
        let checker_pmu_type = detect_pmu_type_cached(*checker_cpu_set.first().unwrap_or(&0));

        info!("Detected PMU type for main = {:?}", main_pmu_type);
        info!("Detected PMU type for checker = {:?}", checker_pmu_type);

        Self {
            main_branch_counter: Mutex::new(None),
            segment_info_map: Mutex::new(HashMap::new()),
            main_pmu_type,
            checker_pmu_type,
            is_test,
            checkpoint_count: AtomicU64::new(0),
            branch_counter_type,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_cpuid_overrides(&self) -> Vec<CpuidOverride> {
        let mut results = Vec::new();

        if self.main_pmu_type != self.checker_pmu_type
            && (matches!(self.main_pmu_type, PmuType::IntelMont { in_hybrid: true })
                || matches!(
                    self.checker_pmu_type,
                    PmuType::IntelMont { in_hybrid: true }
                ))
        {
            // Quirk: Workaround Intel Gracemont microarchitecture overcounting xsave/xsavec instructions as conditional branch
            results.extend(cpuid::overrides::NO_XSAVE);

            info!("Disabling xsave instructions")
        }

        results
    }
}

impl SegmentEventHandler for PerfCounterBasedExecutionPointProvider {
    fn handle_checkpoint_created_pre(&self, _main: &mut Main) -> Result<()> {
        let mut t = self.main_branch_counter.lock();
        let counter = t.as_mut().unwrap();
        counter.reset()?;
        counter.enable()?;
        Ok(())
    }

    fn handle_segment_created(&self, main: &mut Main) -> Result<()> {
        self.segment_info_map.lock().insert(
            main.segment.as_ref().unwrap().nr,
            Arc::new(Mutex::new(SegmentInfo {
                checker_branch_counter: None,
                active_exec_point: None,
                upcoming_exec_points: LinkedList::new(),
            })),
        );

        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker) -> Result<()> {
        let segment_info_map = self.segment_info_map.lock();

        let mut segment_info = segment_info_map.get(&checker.segment.nr).unwrap().lock();

        segment_info.checker_branch_counter =
            Some(LinuxPerfCounter::count_branches_with_interrupt(
                self.checker_pmu_type,
                self.branch_counter_type,
                checker.process.pid,
                None,
            )?);

        self.activate_first_exec_point_in_queue(checker, &mut segment_info)?;

        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<crate::types::segment::Segment>) -> Result<()> {
        self.segment_info_map.lock().remove(&segment.nr);
        Ok(())
    }
}

impl ProcessLifetimeHook for PerfCounterBasedExecutionPointProvider {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        *self.main_branch_counter.lock() = Some(LinuxPerfCounter::count_branches_with_interrupt(
            self.main_pmu_type,
            self.branch_counter_type,
            context.process.pid,
            None,
        )?);

        Ok(())
    }
}

impl PerfCounterBasedExecutionPointProvider {
    fn activate_first_exec_point_in_queue(
        &self,
        checker: &mut Checker,
        segment_info: &mut SegmentInfo,
    ) -> Result<()> {
        if segment_info.active_exec_point.is_some() {
            debug!("{checker} Ignoring execution point activation request because there is already an active one");
            return Ok(());
        }

        if let Some(exec_point) = segment_info.upcoming_exec_points.pop_front() {
            debug!("{checker} Set up exec point {exec_point:?}");

            let branch_count_curr = segment_info
                .checker_branch_counter
                .as_mut()
                .map(|x| x.read())
                .unwrap_or(Ok(0))?;

            assert!(exec_point.branch_counter >= branch_count_curr);

            let initial_state;

            if exec_point.branch_counter - branch_count_curr
                <= self.checker_pmu_type.max_skid() + self.checker_pmu_type.min_irq_period()
            {
                debug!("{checker} ... using breakpoint");
                initial_state = ExecutionPointReplayState::Stepping {
                    breakpoint: Box::new(LinuxPerfCounter::interrupt_on_breakpoint(
                        checker.process.pid,
                        exec_point.instruction_pointer,
                    )?),
                };
            } else {
                debug!("{checker} ... using branch count overflow interrupt");
                initial_state = ExecutionPointReplayState::CountingBranches {
                    branch_irq: LinuxPerfCounter::count_branches_with_interrupt(
                        self.checker_pmu_type,
                        self.branch_counter_type,
                        checker.process.pid,
                        Some(
                            exec_point.branch_counter
                                - branch_count_curr
                                - self.checker_pmu_type.max_skid(),
                        ),
                    )?,
                };
            }

            segment_info.active_exec_point = Some((exec_point, initial_state));
        }
        Ok(())
    }
}

impl SignalHandler for PerfCounterBasedExecutionPointProvider {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        let mut handled = false;

        match context.child {
            InferiorRefMut::Checker(checker) => {
                if checker.process.get_sigval()? == Some(Self::SIGVAL_CHECKER_PREPARE_EXEC_POINT) {
                    debug!("{checker} Received sigval for preparing exec point");

                    self.activate_first_exec_point_in_queue(
                        checker,
                        &mut self
                            .segment_info_map
                            .lock()
                            .get(&checker.segment.nr)
                            .map(|x| x.clone())
                            .unwrap()
                            .lock(),
                    )?;

                    handled = true;
                } else if let Some(segment_info) = self
                    .segment_info_map
                    .lock()
                    .get(&checker.segment.nr)
                    .cloned()
                {
                    let mut segment_info = segment_info.lock();
                    if let Some((exec_point, mut state)) = segment_info.active_exec_point.take() {
                        let mut replay_done = false;

                        match &state {
                            ExecutionPointReplayState::CountingBranches { branch_irq } => {
                                if branch_irq.is_interrupt(signal, &checker.process.as_ref())? {
                                    debug!("{checker} Branch count interrupt fired, setting up breakpoint");

                                    state = ExecutionPointReplayState::Stepping {
                                        breakpoint: Box::new(
                                            LinuxPerfCounter::interrupt_on_breakpoint(
                                                checker.process.pid,
                                                exec_point.instruction_pointer,
                                            )?,
                                        ),
                                    };

                                    handled = true;
                                }
                            }
                            ExecutionPointReplayState::Stepping { breakpoint } => {
                                if breakpoint.is_interrupt(signal, &checker.process.as_ref())? {
                                    debug!("{checker} Breakpoint hit");

                                    debug_assert_eq!(
                                        checker.process.read_registers()?.ip(),
                                        exec_point.instruction_pointer
                                    );

                                    let branch_count_curr = segment_info
                                        .checker_branch_counter
                                        .as_mut()
                                        .unwrap()
                                        .read()?;

                                    let branch_count_target = exec_point.branch_counter;

                                    debug!("{checker} Current branch count = {branch_count_curr}, target count = {branch_count_target}");

                                    match branch_count_curr.cmp(&branch_count_target) {
                                        std::cmp::Ordering::Less => {
                                            // keep going
                                        }
                                        std::cmp::Ordering::Equal => {
                                            debug!(
                                                "{checker} Reached execution point {exec_point:?}"
                                            );

                                            #[cfg(target_arch = "x86_64")]
                                            checker.process.modify_registers_with(|r| {
                                                r.with_resume_flag_cleared()
                                            })?;

                                            replay_done = true;
                                        }
                                        std::cmp::Ordering::Greater => {
                                            unreachable!("Unexpected skid");
                                        }
                                    }

                                    handled = true;
                                }
                            }
                        }

                        if replay_done {
                            debug!("{checker} Execution point replay finished");
                            self.activate_first_exec_point_in_queue(checker, &mut segment_info)?;
                            let result = checker.segment.record.pop_execution_point()?;

                            if !result.value.do_eq(&exec_point) {
                                error!("{checker} Execution point is not equal ({exec_point:?} != {:?})", result.value);
                                return Err(Error::UnexpectedEvent(
                                    UnexpectedEventReason::IncorrectTypeOrArguments,
                                ));
                            }

                            if result.is_last_event {
                                return Ok(SignalHandlerExitAction::Checkpoint);
                            }
                        } else {
                            segment_info.active_exec_point = Some((exec_point, state));
                        }
                    }
                }
            }
            _ => (),
        }

        if handled {
            Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior)
        } else {
            Ok(SignalHandlerExitAction::NextHandler)
        }
    }
}

impl StatisticsProvider for PerfCounterBasedExecutionPointProvider {
    fn class_name(&self) -> &'static str {
        "pmu_segmentor"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn crate::statistics::StatisticValue>)]> {
        statistics_list!(checkpoint_count = self.checkpoint_count.load(Ordering::Relaxed))
    }
}

impl ExecutionPointProvider for PerfCounterBasedExecutionPointProvider {
    fn get_current_execution_point(
        &self,
        child: &mut InferiorRefMut,
    ) -> Result<Arc<dyn ExecutionPoint>> {
        match child {
            InferiorRefMut::Main(main) => {
                let branches_executed = self.main_branch_counter.lock().as_mut().unwrap().read()?;

                let segment_info_map = self.segment_info_map.lock();

                Ok(Arc::new(BranchCounterBasedExecutionPoint {
                    branch_counter: branches_executed,
                    instruction_pointer: main.process.read_registers()?.ip(),
                    ty: self.branch_counter_type,
                    segment_info: segment_info_map
                        .get(&main.segment.as_ref().unwrap().nr)
                        .unwrap()
                        .clone(),
                }))
            }
            InferiorRefMut::Checker(checker) => {
                let segment_info_map = self.segment_info_map.lock();
                let segment_info_arc = segment_info_map.get(&checker.segment.nr).unwrap();
                let mut segment_info = segment_info_arc.lock();

                let branch_counter = segment_info.checker_branch_counter.as_mut().unwrap();

                Ok(Arc::new(BranchCounterBasedExecutionPoint {
                    branch_counter: branch_counter.read()?,
                    instruction_pointer: checker.process.read_registers()?.ip(),
                    ty: self.branch_counter_type,
                    segment_info: segment_info_arc.clone(),
                }))
            }
        }
    }
}

impl ModuleLifetimeHook for PerfCounterBasedExecutionPointProvider {
    fn fini<'s, 'scope, 'env>(
        &'s self,
        _scope: &'scope std::thread::Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
    {
        if self.is_test {
            let segment_info_map = self.segment_info_map.lock();
            assert!(segment_info_map.is_empty());
        }
        Ok(())
    }
}

impl Module for PerfCounterBasedExecutionPointProvider {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_signal_handler(self);
        subs.install_stats_providers(self);
        subs.set_execution_point_provider(self);
        subs.install_module_lifetime_hook(self);
        subs.install_process_lifetime_hook(self);
    }
}
