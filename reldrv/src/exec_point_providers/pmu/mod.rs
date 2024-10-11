//! PMU-interrupt-based segmentation
pub mod exec_point;

use std::{
    collections::{HashMap, LinkedList},
    fmt::Debug,
    sync::Arc,
};

use derivative::Derivative;
use exec_point::BranchCounterBasedExecutionPoint;
use log::{debug, error};

use nix::{sys::signal::Signal, unistd::Pid};
use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    events::{
        exec_point::ExecutionPointEventHandler,
        migration::MigrationHandler,
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{
        memory::instructions,
        registers::RegisterAccess,
        siginfo::SigInfoExt,
        state::{Running, Stopped},
        Process,
    },
    types::{
        breakpoint::{breakpoint, Breakpoint},
        checker_exec::CheckerExecutionId,
        execution_point::{ExecutionPoint, ExecutionPointOwner},
        perf_counter::{
            symbolic_events::{
                expr::{lookup_cpu_model_and_pmu_name_from_cpu_set, Target},
                BranchCounter, BranchCounterWithInterrupt, BranchType,
            },
            PerfCounter, PerfCounterWithInterrupt,
        },
        process_id::{Checker, InferiorRefMut, Main},
        segment::SegmentId,
    },
};

#[cfg(target_arch = "x86_64")]
use crate::{
    signal_handlers::cpuid::{self, CpuidOverride},
    types::perf_counter::cpu_info::CpuModel,
};

use super::ExecutionPointProvider;

#[derive(Derivative)]
#[derivative(Debug)]
pub struct ExecInfo {
    branch_type: BranchType,
    branch_count_offset: u64,
    #[derivative(Debug = "ignore")]
    checker_branch_counter: Option<BranchCounter>,
    active_exec_point: Option<(
        BranchCounterBasedExecutionPoint,
        ExecutionPointOwner,
        ExecutionPointReplayState,
    )>,
    upcoming_exec_points: LinkedList<(BranchCounterBasedExecutionPoint, ExecutionPointOwner)>,
}

impl ExecInfo {
    pub fn current_branch_count(&mut self) -> std::io::Result<u64> {
        let pmc = self
            .checker_branch_counter
            .as_mut()
            .map_or(Ok(0), |x| x.read())?;

        Ok(pmc + self.branch_count_offset)
    }

    pub fn init_or_migrate_branch_counter(
        &mut self,
        pid: Pid,
        cpu_set: &[usize],
        reset: bool,
    ) -> Result<()> {
        let new_counter = BranchCounter::new(self.branch_type, Target::Pid(pid), true, cpu_set)?;

        if reset {
            self.branch_count_offset = 0;
            self.checker_branch_counter = Some(new_counter);
        } else {
            if let Some(mut old_counter) = self.checker_branch_counter.replace(new_counter) {
                self.branch_count_offset += old_counter.read()?;
            }
        }

        Ok(())
    }

    pub fn migrate(
        &mut self,
        checker_process: &mut Process<Stopped>,
        new_cpu_set: &[usize],
    ) -> Result<()> {
        self.init_or_migrate_branch_counter(checker_process.pid, new_cpu_set, false)?;

        if let Some((exec_point, _, state)) = self.active_exec_point.as_mut() {
            if let ExecutionPointReplayState::CountingBranches { .. } = state {
                *state = ExecutionPointReplayState::setup(
                    exec_point,
                    self.checker_branch_counter
                        .as_mut()
                        .map_or(Ok(0), |x| x.read())?
                        + self.branch_count_offset,
                    new_cpu_set,
                    checker_process,
                    self.branch_type,
                    false,
                )?;
            }
        }

        Ok(())
    }

    pub fn clear(&mut self) {
        self.branch_count_offset = 0;
        self.checker_branch_counter = None;
        self.active_exec_point = None;
        self.upcoming_exec_points.clear();
    }

    pub fn add_exec_point_to_queue(
        &mut self,
        ep: BranchCounterBasedExecutionPoint,
        owner: ExecutionPointOwner,
    ) -> Result<()> {
        let mut new_list = LinkedList::new();
        let mut new_ep = Some(ep);

        while let Some((e_ep, e_owner)) = self.upcoming_exec_points.pop_front() {
            if let Some(n_ep) = &new_ep {
                if &e_ep > n_ep {
                    new_list.push_back((n_ep.clone(), owner));
                    new_ep = None;
                }
            }
            new_list.push_back((e_ep, e_owner));
        }

        if let Some(n_ep) = new_ep.take() {
            new_list.push_back((n_ep, owner));
        }

        self.upcoming_exec_points = new_list;
        Ok(())
    }
}

enum ExecutionPointReplayState {
    CountingBranches {
        branch_irq: BranchCounterWithInterrupt,
    },
    Stepping {
        breakpoint: Box<dyn Breakpoint>,
        breakpoint_suspended: bool,
        single_stepping: bool,
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

impl ExecutionPointReplayState {
    pub fn setup(
        exec_point: &BranchCounterBasedExecutionPoint,
        branch_count_curr: u64,
        cpu_set: &[usize],
        checker_process: &mut Process<Stopped>,
        branch_type: BranchType,
        checker_never_use_branch_count_overflow: bool,
    ) -> Result<ExecutionPointReplayState> {
        let state;
        let checker_cpu_model = lookup_cpu_model_and_pmu_name_from_cpu_set(cpu_set)
            .unwrap()
            .0;

        if exec_point.branch_count - branch_count_curr
            <= checker_cpu_model.max_skid() + checker_cpu_model.min_irq_period()
            || checker_never_use_branch_count_overflow
        {
            state = ExecutionPointReplayState::Stepping {
                breakpoint: breakpoint(checker_process, exec_point.instruction_pointer)?,
                breakpoint_suspended: false,
                single_stepping: false,
            };
        } else {
            state = ExecutionPointReplayState::CountingBranches {
                branch_irq: BranchCounterWithInterrupt::new(
                    branch_type,
                    checker_process.pid,
                    true,
                    cpu_set,
                    exec_point.branch_count - branch_count_curr - checker_cpu_model.max_skid(),
                    None,
                )?,
            };
        }

        Ok(state)
    }
}

pub struct PerfCounterBasedExecutionPointProvider<'a> {
    exec_info_map:
        Arc<Mutex<HashMap<SegmentId, HashMap<CheckerExecutionId, Arc<Mutex<ExecInfo>>>>>>,
    main_branch_counter: Mutex<Option<BranchCounter>>,
    main_cpu_set: &'a [usize],
    #[cfg(target_arch = "x86_64")]
    main_cpu_model: CpuModel,
    branch_counter_type: BranchType,
    checker_never_use_branch_count_overflow: bool,
}

impl<'a> PerfCounterBasedExecutionPointProvider<'a> {
    pub(self) const SIGVAL_CHECKER_PREPARE_EXEC_POINT: usize = 0xeb5aadf82a35bd9f;

    pub fn new(
        main_cpu_set: &'a [usize],
        branch_counter_type: BranchType,
        checker_never_use_branch_count_overflow: bool,
    ) -> Self {
        Self {
            main_branch_counter: Mutex::new(None),
            exec_info_map: Arc::new(Mutex::new(HashMap::new())),
            main_cpu_set,
            #[cfg(target_arch = "x86_64")]
            main_cpu_model: lookup_cpu_model_and_pmu_name_from_cpu_set(main_cpu_set)
                .unwrap()
                .0,
            branch_counter_type,
            checker_never_use_branch_count_overflow,
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn get_cpuid_overrides(&self) -> Vec<CpuidOverride> {
        let mut results = Vec::new();

        if self.main_cpu_model == CpuModel::IntelLakeCove
            || self.main_cpu_model == CpuModel::IntelLakeCove
        {
            // Quirk: Workaround Intel Gracemont microarchitecture overcounting xsave/xsavec instructions as conditional branch
            results.extend(cpuid::overrides::NO_XSAVE);

            log::info!("Disabling xsave instructions")
        }

        results
    }
}

impl SegmentEventHandler for PerfCounterBasedExecutionPointProvider<'_> {
    fn handle_checkpoint_created_post_fork(
        &self,
        _main: &mut Main<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut t = self.main_branch_counter.lock();
        let counter = t.as_mut().unwrap();
        counter.reset()?;
        counter.enable()?;
        Ok(())
    }

    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        self.exec_info_map
            .lock()
            .entry(main.segment.as_ref().unwrap().nr)
            .or_default();

        Ok(())
    }

    fn handle_checker_exec_created(
        &self,
        segment: &Arc<crate::types::segment::Segment>,
        exec: &Arc<crate::types::checker_exec::CheckerExecution>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut exec_info_map = self.exec_info_map.lock();

        let exec_info = Arc::new(Mutex::new(ExecInfo {
            branch_count_offset: 0,
            checker_branch_counter: None,
            active_exec_point: None,
            upcoming_exec_points: LinkedList::new(),
            branch_type: self.branch_counter_type,
        }));

        exec_info_map
            .get_mut(&segment.nr)
            .unwrap()
            .insert(exec.id, exec_info.clone());

        Ok(())
    }

    fn handle_checker_exec_ready(
        &self,
        checker: &mut Checker<Stopped>,
        ctx: HandlerContext,
    ) -> Result<()> {
        let exec_info_map = self.exec_info_map.lock();

        let mut exec_info = exec_info_map
            .get(&checker.segment.nr)
            .unwrap()
            .get(&checker.exec.id)
            .unwrap()
            .lock();

        let checker_status = checker.exec.status.lock();
        let checker_cpu_set = checker_status.cpu_set().unwrap();

        exec_info.init_or_migrate_branch_counter(checker.process().pid, checker_cpu_set, true)?;

        drop(checker_status);

        self.activate_first_exec_point_in_queue(
            checker,
            &mut exec_info,
            ctx.check_coord.dispatcher,
        )?;

        Ok(())
    }

    fn handle_checker_exec_completed(
        &self,
        checker: &mut Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut exec_info_map = self.exec_info_map.lock();
        exec_info_map
            .get_mut(&checker.segment.nr)
            .unwrap()
            .remove(&checker.exec.id)
            .unwrap();

        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<crate::types::segment::Segment>) -> Result<()> {
        self.exec_info_map.lock().remove(&segment.nr);
        Ok(())
    }
}

impl ProcessLifetimeHook for PerfCounterBasedExecutionPointProvider<'_> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        *self.main_branch_counter.lock() = Some(BranchCounter::new(
            self.branch_counter_type,
            Target::Pid(main.process().pid),
            true,
            self.main_cpu_set,
        )?);

        Ok(())
    }
}

impl PerfCounterBasedExecutionPointProvider<'_> {
    fn handle_exec_point_reached(
        &self,
        ep: &BranchCounterBasedExecutionPoint,
        owner: ExecutionPointOwner,
        checker: &mut Checker<Stopped>,
        dispatcher: &impl ExecutionPointEventHandler,
    ) -> Result<SignalHandlerExitAction> {
        match owner {
            ExecutionPointOwner::SegmentRecord => checker
                .exec
                .clone()
                .replay
                .handle_exec_point_reached(ep, checker),
            ExecutionPointOwner::Freestanding => {
                dispatcher.handle_freestanding_exec_point_reached(ep, checker)?;
                Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                    single_step: false,
                })
            }
        }
    }

    fn activate_first_exec_point_in_queue(
        &self,
        checker: &mut Checker<Stopped>,
        exec_info: &mut ExecInfo,
        dispatcher: &impl ExecutionPointEventHandler,
    ) -> Result<Option<SignalHandlerExitAction>> {
        let mut ep_to_activate = None;

        if let Some((active_ep, _, _)) = &exec_info.active_exec_point {
            let mut replaced = false;

            if let Some((first_ep, first_ep_owner)) = exec_info.upcoming_exec_points.front() {
                if first_ep < active_ep {
                    debug!("{checker} Replacing active exec point with the upcoming one");
                    ep_to_activate = Some((first_ep.clone(), *first_ep_owner));

                    let (active_ep, active_ep_owner, state) =
                        exec_info.active_exec_point.take().unwrap();

                    match state {
                        ExecutionPointReplayState::Stepping { mut breakpoint, .. } => {
                            breakpoint.disable(checker.process_mut())?;
                        }
                        _ => (),
                    }

                    exec_info.add_exec_point_to_queue(active_ep, active_ep_owner)?;
                    replaced = true;
                }
            }

            if !replaced {
                return Ok(None);
            }
        }

        if ep_to_activate.is_none() {
            if let Some(first) = exec_info.upcoming_exec_points.pop_front() {
                assert!(exec_info.active_exec_point.is_none());
                ep_to_activate = Some(first);
            }
        }

        if let Some((exec_point, owner)) = ep_to_activate.take() {
            let branch_count_curr = exec_info.current_branch_count()?;
            assert!(exec_point.branch_count >= branch_count_curr);

            if exec_point.branch_count == branch_count_curr
                && exec_point.instruction_pointer == checker.process().read_registers()?.ip()
            {
                let result =
                    self.handle_exec_point_reached(&exec_point, owner, checker, dispatcher)?;

                assert!(self
                    .activate_first_exec_point_in_queue(checker, exec_info, dispatcher)?
                    .is_none());

                return Ok(Some(result));
            }

            let replay_state = ExecutionPointReplayState::setup(
                &exec_point,
                branch_count_curr,
                checker.exec.status.lock().cpu_set().unwrap(),
                checker.process.as_mut().unwrap(),
                self.branch_counter_type,
                self.checker_never_use_branch_count_overflow,
            )?;

            debug!("{checker} Set up exec point {exec_point:?}, current branch count = {branch_count_curr}, replay state = {replay_state:?}");

            exec_info.active_exec_point = Some((exec_point, owner, replay_state));
        }
        Ok(None)
    }
}

impl SignalHandler for PerfCounterBasedExecutionPointProvider<'_> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP && signal != Signal::SIGUSR1 {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        let mut handled = false;
        let mut do_single_step = false;

        match context.child {
            InferiorRefMut::Checker(checker) => {
                if checker.process().get_sigval()? == Some(Self::SIGVAL_CHECKER_PREPARE_EXEC_POINT)
                {
                    debug!("{checker} Received sigval for preparing exec point");

                    let result = self.activate_first_exec_point_in_queue(
                        checker,
                        &mut self
                            .exec_info_map
                            .lock()
                            .get(&checker.segment.nr)
                            .unwrap()
                            .get(&checker.exec.id)
                            .map(|x| x.clone())
                            .unwrap()
                            .lock(),
                        context.check_coord.dispatcher,
                    )?;

                    if let Some(result) = result {
                        return Ok(result);
                    }

                    handled = true;
                } else if let Some(exec_info) = self
                    .exec_info_map
                    .lock()
                    .get(&checker.segment.nr)
                    .and_then(|h| h.get(&checker.exec.id))
                    .cloned()
                {
                    let mut exec_info = exec_info.lock();
                    if let Some((exec_point, owner, mut state)) = exec_info.active_exec_point.take()
                    {
                        let mut replay_done = false;

                        let sig_info = checker.process().get_siginfo()?;

                        match &mut state {
                            ExecutionPointReplayState::CountingBranches { branch_irq } => {
                                if branch_irq.is_interrupt(&sig_info)? {
                                    debug!("{checker} Branch count interrupt fired, setting up breakpoint");

                                    state = ExecutionPointReplayState::Stepping {
                                        breakpoint: breakpoint(
                                            checker.process_mut(),
                                            exec_point.instruction_pointer,
                                        )?,
                                        breakpoint_suspended: false,
                                        single_stepping: false,
                                    };

                                    handled = true;
                                }
                            }
                            ExecutionPointReplayState::Stepping {
                                breakpoint,
                                breakpoint_suspended,
                                single_stepping,
                            } => {
                                if breakpoint.is_hit(checker.process())? {
                                    debug!("{checker} Breakpoint hit");

                                    breakpoint.fix_after_hit(checker.process_mut())?;

                                    assert!(!*breakpoint_suspended);
                                    assert!(!*single_stepping);

                                    debug_assert_eq!(
                                        checker.process().read_registers()?.ip(),
                                        exec_point.instruction_pointer
                                    );

                                    let branch_count_curr = exec_info.current_branch_count()?;

                                    let branch_count_target = exec_point.branch_count;

                                    debug!("{checker} Current branch count = {branch_count_curr}, target count = {branch_count_target}");

                                    match branch_count_curr.cmp(&branch_count_target) {
                                        std::cmp::Ordering::Less => {
                                            // keep going

                                            if breakpoint
                                                .characteristics()
                                                .needs_single_step_after_hit
                                            {
                                                let regs = checker.process().read_registers()?;

                                                if breakpoint
                                                    .characteristics()
                                                    .needs_bp_disabled_during_single_stepping
                                                {
                                                    debug!("{checker} Disabling breakpoint for single stepping");
                                                    breakpoint.disable(checker.process_mut())?;
                                                    *breakpoint_suspended = true;
                                                }

                                                if !checker
                                                    .process()
                                                    .instr_eq(regs.ip(), instructions::SYSCALL)
                                                {
                                                    // PTRACE_SINGLESTEP will
                                                    // miss syscalls, so we can
                                                    // only do PTRACE_SYSCALL
                                                    // when the next instruction
                                                    // is a syscall
                                                    do_single_step = true;
                                                    *single_stepping = true;
                                                } else {
                                                    debug!("{checker} Next instruction is a syscall, skipping single stepping");
                                                }
                                            }
                                        }
                                        std::cmp::Ordering::Equal => {
                                            breakpoint.disable(checker.process_mut())?;

                                            #[cfg(target_arch = "x86_64")]
                                            checker.process_mut().modify_registers_with(|r| {
                                                r.with_resume_flag_cleared()
                                            })?;

                                            debug!(
                                                "{checker} Reached execution point: {exec_point}"
                                            );

                                            replay_done = true;
                                        }
                                        std::cmp::Ordering::Greater => {
                                            breakpoint.disable(checker.process_mut())?;
                                            error!("{checker} Unexpected skid during execution point replay");
                                            return Err(Error::ExecPointReplayUnexpectedSkid);
                                        }
                                    }

                                    handled = true;
                                } else if checker.process().get_siginfo()?.is_trap_trace() {
                                    if *single_stepping {
                                        debug!("{checker} Single step trap");
                                        *single_stepping = false;

                                        if *breakpoint_suspended {
                                            debug!("{checker} Resuming breakpoint");
                                            *breakpoint_suspended = false;
                                            breakpoint.enable(checker.process_mut())?;
                                        }

                                        handled = true;
                                    }
                                }
                            }
                        }

                        if replay_done {
                            debug!("{checker} Execution point replay finished");
                            self.activate_first_exec_point_in_queue(
                                checker,
                                &mut exec_info,
                                context.check_coord.dispatcher,
                            )?;
                            return self.handle_exec_point_reached(
                                &exec_point,
                                owner,
                                checker,
                                context.check_coord.dispatcher,
                            );
                        } else {
                            exec_info.active_exec_point = Some((exec_point, owner, state));
                        }
                    }
                }
            }
            _ => (),
        }

        if handled {
            Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                single_step: do_single_step,
            })
        } else {
            Ok(SignalHandlerExitAction::NextHandler)
        }
    }
}

impl StandardSyscallHandler for PerfCounterBasedExecutionPointProvider<'_> {
    fn handle_standard_syscall_exit(
        &self,
        _ret_val: isize,
        _syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        if let InferiorRefMut::Checker(checker) = context.child {
            let segment_id = checker.segment.nr;
            let exec_info_map = self.exec_info_map.lock();
            if let Some(exec_info) = exec_info_map
                .get(&segment_id)
                .and_then(|h| h.get(&checker.exec.id))
            {
                let mut exec_info = exec_info.lock();
                match &mut exec_info.active_exec_point {
                    Some((
                        _,
                        _,
                        ExecutionPointReplayState::Stepping {
                            breakpoint,
                            breakpoint_suspended,
                            single_stepping,
                        },
                    )) => {
                        assert!(!*single_stepping);
                        if *breakpoint_suspended {
                            debug!("Resuming breakpoint");
                            *breakpoint_suspended = false;
                            breakpoint.enable(context.child.process_mut())?;
                        }
                    }
                    _ => (),
                }
            }
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ExecutionPointProvider for PerfCounterBasedExecutionPointProvider<'_> {
    fn get_current_execution_point(
        &self,
        child: &mut InferiorRefMut<Stopped>,
    ) -> Result<Arc<dyn ExecutionPoint>> {
        match child {
            InferiorRefMut::Main(main) => {
                let branches_executed = self.main_branch_counter.lock().as_mut().unwrap().read()?;

                Ok(Arc::new(BranchCounterBasedExecutionPoint {
                    branch_count: branches_executed,
                    instruction_pointer: main.process().read_registers()?.ip(),
                    ty: self.branch_counter_type,
                    exec_info_map: self.exec_info_map.clone(),
                }))
            }
            InferiorRefMut::Checker(checker) => {
                let exec_info_map = self.exec_info_map.lock();
                let exec_info_arc = exec_info_map
                    .get(&checker.segment.nr)
                    .unwrap()
                    .get(&checker.exec.id)
                    .unwrap();

                let mut exec_info = exec_info_arc.lock();

                let branch_count = exec_info.current_branch_count()?;

                Ok(Arc::new(BranchCounterBasedExecutionPoint {
                    branch_count,
                    instruction_pointer: checker.process().read_registers()?.ip(),
                    ty: self.branch_counter_type,
                    exec_info_map: self.exec_info_map.clone(),
                }))
            }
        }
    }
}

impl MigrationHandler for PerfCounterBasedExecutionPointProvider<'_> {
    fn handle_checker_migration(&self, context: HandlerContextWithInferior<Stopped>) -> Result<()> {
        let exec_info_map = self.exec_info_map.lock();
        let checker = context.child.unwrap_checker_mut();
        let exec_info = exec_info_map
            .get(&checker.segment.nr)
            .unwrap()
            .get(&checker.exec.id)
            .unwrap();

        let mut exec_info = exec_info.lock();
        let checker_status = checker.exec.status.lock();
        let new_cpu_set = checker_status.cpu_set().unwrap();

        exec_info.migrate(checker.process.as_mut().unwrap(), new_cpu_set)?;
        debug!("{checker} Migrating to CPU set: {new_cpu_set:?}");
        debug!("{checker} Current state: {exec_info:?}");

        Ok(())
    }
}

impl Module for PerfCounterBasedExecutionPointProvider<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_signal_handler(self);
        subs.set_execution_point_provider(self);
        subs.install_process_lifetime_hook(self);
        subs.install_standard_syscall_handler(self);
        subs.install_migration_handler(self);
    }
}
