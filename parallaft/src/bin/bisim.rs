use core::panic;
use std::{
    collections::HashMap,
    fs::OpenOptions,
    path::PathBuf,
    process::Command,
    sync::{atomic::AtomicU64, Arc},
};

use clap::Parser;
use derivative::Derivative;
use git_version::git_version;
use log::info;
use nix::sys::signal::Signal;
use parallaft::{
    dispatcher::Module,
    events::{
        exec_point::ExecutionPointEventHandler,
        process_lifetime::HandlerContext,
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    exec_point_providers::ExecutionPointProvider,
    process::{
        registers::{RegisterAccess, Registers},
        state::{ProcessState, Running, Stopped},
    },
    types::{
        checker_exec::{CheckerExecution, CheckerExecutionId},
        checker_status::CheckFailReason,
        checkpoint::{Checkpoint, CheckpointCaller},
        execution_point::{ExecutionPoint, ExecutionPointOwner},
        exit_reason::ExitReason,
        perf_counter::{
            symbolic_events::{
                GenericHardwareEventCounter, GenericHardwareEventCounterWithInterrupt,
            },
            PerfCounter, PerfCounterWithInterrupt,
        },
        process_id::{Checker, InferiorRefMut, Main},
        segment::{Segment, SegmentId},
    },
    RelShellOptions,
};
use parking_lot::{Condvar, Mutex};
use perf_event::events::Hardware;

#[derive(Parser, Debug)]
#[command(version = git_version!())]
struct CliArgs {
    /// Config file to use
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Don't actually inject errors
    #[arg(short, long)]
    dry_run: bool,

    /// Result output filename
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Append instead of rewriting to the output file
    #[arg(long)]
    append: bool,

    command: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ExecutionOutcome {
    Benigh,
    Detected,
    Exception,
    Timeout,
    Other,
}

impl From<&parallaft::error::Error> for ExecutionOutcome {
    fn from(value: &parallaft::error::Error) -> Self {
        match value {
            parallaft::error::Error::CheckerTimeout => ExecutionOutcome::Timeout,
            parallaft::error::Error::ExecPointReplayUnexpectedSkid
            | parallaft::error::Error::UnexpectedEvent(_) => ExecutionOutcome::Detected,
            parallaft::error::Error::UnexpectedCheckerExitReason(ExitReason::Signalled(sig))
                if [Signal::SIGSEGV, Signal::SIGBUS, Signal::SIGILL].contains(sig) =>
            {
                ExecutionOutcome::Exception
            }
            _ => ExecutionOutcome::Other,
        }
    }
}

#[derive(Debug)]
struct RaftLikeExecution {
    in_initial_segment: bool,
    initial_segment: Arc<Segment>,
    segment: Arc<Segment>,
    exec: Arc<CheckerExecution>,
    outcome: Option<ExecutionOutcome>,
}

#[derive(Debug)]
struct ParaHeteroExecution {
    outcome: Option<ExecutionOutcome>,
}

#[derive(Debug)]
enum Execution {
    RaftLikeExecution(RaftLikeExecution),
    ParaHeteroExecution(ParaHeteroExecution),
}

impl Execution {
    fn outcome(&self) -> Option<ExecutionOutcome> {
        match self {
            Self::RaftLikeExecution(RaftLikeExecution { outcome, .. }) => *outcome,
            Self::ParaHeteroExecution(ParaHeteroExecution { outcome, .. }) => *outcome,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
enum ExecType {
    RaftLike,
    ParaHetero,
}

#[derive(Derivative)]
#[derivative(Debug)]
enum SegmentStatus {
    New,
    Training {
        #[derivative(Debug = "ignore")]
        cycle_counter: GenericHardwareEventCounter,
    },
    Randomizing {
        cycles: u64,
        #[derivative(Debug = "ignore")]
        irq: Option<GenericHardwareEventCounterWithInterrupt>,
    },
    Injecting {
        exec_point: Arc<dyn ExecutionPoint>,
        registers_without_fault: Registers,
        registers_with_fault: Registers,
        execs: HashMap<CheckerExecutionId, Arc<Mutex<Execution>>>,
    },
}

#[derive(Debug)]
struct SegmentState {
    status: SegmentStatus,
}

impl SegmentState {
    fn new() -> Self {
        Self {
            status: SegmentStatus::New,
        }
    }
}

struct BisimErrorInjector {
    stats: Arc<Mutex<HashMap<ExecType, HashMap<ExecutionOutcome, u64>>>>,
    segments: Mutex<HashMap<SegmentId, Arc<Mutex<SegmentState>>>>,
}

impl BisimErrorInjector {
    fn new(stats: Arc<Mutex<HashMap<ExecType, HashMap<ExecutionOutcome, u64>>>>) -> Self {
        Self {
            stats,
            segments: Mutex::new(HashMap::new()),
        }
    }

    fn incr_stat(&self, exec_type: ExecType, outcome: ExecutionOutcome) {
        info!("{exec_type:?} outcome: {outcome:?}");

        *self
            .stats
            .lock()
            .entry(exec_type)
            .or_default()
            .entry(outcome)
            .or_default() += 1;
    }
}

fn initial_segment_nr(segment: &Segment, exec: &CheckerExecution) -> SegmentId {
    if exec.id & EXEC_ID_RAFT_LIKE_BIT != 0 {
        exec.id & EXEC_ID_RAFT_LIKE_INITIAL_NR_MASK
    } else {
        segment.nr
    }
}

trait InitialSegmentNrExt {
    fn initial_segment_nr(&self) -> SegmentId;
}

const EXEC_ID_RAFT_LIKE_BIT: u64 = 1 << 63;
const EXEC_ID_RAFT_LIKE_INITIAL_NR_MASK: u64 = (1 << 63) - 1;

impl<S: ProcessState> InitialSegmentNrExt for Checker<S> {
    fn initial_segment_nr(&self) -> SegmentId {
        initial_segment_nr(&self.segment, &self.exec)
    }
}

impl SegmentEventHandler for BisimErrorInjector {
    fn handle_segment_created(&self, main: &mut Main<Running>) -> parallaft::error::Result<()> {
        if let Some(segment) = &main.segment {
            self.segments
                .lock()
                .entry(segment.nr)
                .or_insert_with(|| Arc::new(Mutex::new(SegmentState::new())));

            // *segment.pinned.lock() = true;
        }

        Ok(())
    }

    fn handle_checker_exec_ready(
        &self,
        checker: &mut Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> parallaft::error::Result<()> {
        let state_arc = self
            .segments
            .lock()
            .get_mut(&checker.initial_segment_nr())
            .unwrap()
            .clone();

        let mut state = state_arc.lock();

        match &mut state.status {
            SegmentStatus::New => {
                info!("{checker} Starting training run");
                state.status = SegmentStatus::Training {
                    cycle_counter: GenericHardwareEventCounter::new(
                        Hardware::CPU_CYCLES,
                        parallaft::types::perf_counter::symbolic_events::expr::Target::Pid(
                            checker.process.as_ref().unwrap().pid,
                        ),
                        true,
                        None,
                    )?,
                }
            }
            SegmentStatus::Training { .. } => panic!("Unexpected SegmentStatus::Training"),
            SegmentStatus::Randomizing { cycles, irq } => {
                info!("{checker} Cycles: {cycles}");
                let irq_after = ((*cycles as f64) * rand::random::<f64>() * 1.1) as u64;
                info!("{checker} Interrupting after {irq_after} cycles");

                *irq = Some(GenericHardwareEventCounterWithInterrupt::new(
                    Hardware::CPU_CYCLES,
                    checker.process().pid,
                    true,
                    checker.exec.status.lock().cpu_set().unwrap(),
                    irq_after,
                    None,
                )?);
            }
            SegmentStatus::Injecting {
                exec_point, execs, ..
            } => {
                if let Some(exec) = execs.get(&checker.exec.id) {
                    if !matches!(&*exec.lock(), Execution::RaftLikeExecution(raft_like_exec) if !raft_like_exec.in_initial_segment)
                    {
                        info!("{checker} Preparing execution point for error injection");
                        exec_point.prepare(
                            &checker.segment,
                            &checker.exec,
                            ExecutionPointOwner::Freestanding,
                        )?;
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_checker_exec_completed(
        &self,
        checker: &mut Checker<Stopped>,
        ctx: HandlerContext,
    ) -> parallaft::error::Result<()> {
        let state_arc = self
            .segments
            .lock()
            .get_mut(&checker.initial_segment_nr())
            .unwrap()
            .clone();

        let mut state = state_arc.lock();

        match &mut state.status {
            SegmentStatus::New => panic!("Unexpected SegmentStatus::New"),
            SegmentStatus::Training { cycle_counter } => {
                let cycles = cycle_counter.read()?;
                info!("{checker} Training run finished, cycles: {cycles}");
                state.status = SegmentStatus::Randomizing { cycles, irq: None };
                ctx.check_coord.start_checker_worker_thread(
                    checker.segment.new_checker_exec(true),
                    checker.segment.clone(),
                    ctx.scope,
                )?;
            }
            SegmentStatus::Randomizing { cycles, irq } => {
                let cycles = *cycles;
                info!("{checker} Failed to inject error after {cycles} cycles, retrying");
                *irq = None;
                ctx.check_coord.start_checker_worker_thread(
                    checker.segment.new_checker_exec(true),
                    checker.segment.clone(),
                    ctx.scope,
                )?;
            }
            SegmentStatus::Injecting { execs, .. } => {
                if let Some(exec) = execs.get_mut(&checker.exec.id) {
                    match &mut *exec.clone().lock() {
                        Execution::RaftLikeExecution(raft_like_exec) => {
                            drop(state);

                            info!("{checker} A segment of raft-like error injection run completed");
                            assert_eq!(raft_like_exec.segment.nr, checker.segment.nr);
                            raft_like_exec.in_initial_segment = false;

                            checker.segment.wait_until_main_finished()?;

                            let next_segment = checker.segment.next.lock().clone();

                            if let Some(next_segment) = next_segment {
                                info!(
                                    "{checker} Starting next segment of raft-like error injection run: {}",
                                    next_segment.nr
                                );

                                let checkpoint_process =
                                    checker.try_map_process_inplace(|p| p.fork(true, true))?;

                                let checkpoint_start = Checkpoint::new(
                                    next_segment.checkpoint_start.epoch,
                                    checkpoint_process,
                                    CheckpointCaller::Shell,
                                )?;

                                next_segment.wait_until_main_finished()?;

                                match &*next_segment.status.lock() {
                                    parallaft::types::segment::SegmentStatus::Filling {
                                        ..
                                    } => {
                                        unreachable!()
                                    }
                                    parallaft::types::segment::SegmentStatus::Filled {
                                        is_finishing,
                                        ..
                                    } => {
                                        assert!(checker.exec.id & EXEC_ID_RAFT_LIKE_BIT != 0);

                                        let fake_segment = Arc::new(Segment {
                                            nr: next_segment.nr,
                                            checkpoint_start: Arc::new(checkpoint_start),
                                            status: Mutex::new(
                                                parallaft::types::segment::SegmentStatus::Filled {
                                                    checkpoint: None,
                                                    is_finishing: *is_finishing,
                                                    dirty_page_addresses: None,
                                                },
                                            ),
                                            status_cvar: Condvar::new(),
                                            record: next_segment.record.clone(),
                                            main_checker_exec: next_segment
                                                .main_checker_exec
                                                .clone(),
                                            aux_checker_exec: Mutex::new(HashMap::new()),
                                            pinned: Mutex::new(false),
                                            ongoing_syscall: next_segment.ongoing_syscall,
                                            exec_id: AtomicU64::new(0), // TODO: support multiple injections
                                            next: Mutex::new(next_segment.next.lock().clone()),
                                        });

                                        let fake_exec = fake_segment
                                            .new_checker_exec_with_id(checker.exec.id, true);

                                        assert!(next_segment
                                            .aux_checker_exec
                                            .lock()
                                            .insert(fake_exec.id, fake_exec.clone())
                                            .is_none()); // insert a shadow checker exec to the original segment to prevent segment being cleaned up when we are executing

                                        raft_like_exec.segment = fake_segment.clone();
                                        raft_like_exec.exec = fake_exec.clone();

                                        ctx.check_coord.start_checker_worker_thread(
                                            fake_exec,
                                            fake_segment,
                                            ctx.scope,
                                        )?;
                                    }
                                    parallaft::types::segment::SegmentStatus::Crashed => {
                                        info!("{checker} Next segment crashed");
                                        return Err(parallaft::error::Error::Cancelled);
                                    }
                                }
                            } else {
                                info!("{checker} All segments of raft-like error injection run completed");
                                raft_like_exec.outcome = Some(ExecutionOutcome::Benigh);
                                self.incr_stat(ExecType::RaftLike, ExecutionOutcome::Benigh);
                            }
                        }
                        Execution::ParaHeteroExecution(_) => {
                            info!("{checker} Parallel heterogeneous error injection run completed");
                        }
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_checker_exec_checked(
        &self,
        checker: &mut Checker<Stopped>,
        check_fail_reason: &Option<CheckFailReason>,
        _ctx: HandlerContext,
    ) -> parallaft::error::Result<()> {
        let state_arc = self
            .segments
            .lock()
            .get_mut(&checker.initial_segment_nr())
            .unwrap()
            .clone();

        let mut state = state_arc.lock();

        match &mut state.status {
            SegmentStatus::Injecting { execs, .. } => {
                if let Some(exec) = execs.get_mut(&checker.exec.id) {
                    match &mut *exec.lock() {
                        Execution::RaftLikeExecution(_) => (),
                        Execution::ParaHeteroExecution(para_hetero_exec) => {
                            info!("{checker} Parallel heterogeneous error injection run checked: {check_fail_reason:?}");

                            assert!(para_hetero_exec.outcome.is_none());

                            if check_fail_reason.is_some() {
                                para_hetero_exec.outcome = Some(ExecutionOutcome::Detected);
                                self.incr_stat(ExecType::ParaHetero, ExecutionOutcome::Detected);
                            } else {
                                para_hetero_exec.outcome = Some(ExecutionOutcome::Benigh);
                                self.incr_stat(ExecType::ParaHetero, ExecutionOutcome::Benigh);
                            }
                        }
                    }
                }
            }
            _ => (),
        }

        Ok(())
    }

    fn handle_checker_exec_error(
        &self,
        segment: &Arc<Segment>,
        exec: &Arc<CheckerExecution>,
        error: &parallaft::error::Error,
        abort: &mut bool,
        _ctx: HandlerContext,
    ) -> parallaft::error::Result<()> {
        let state_arc = self
            .segments
            .lock()
            .get_mut(&initial_segment_nr(segment, exec))
            .unwrap()
            .clone();

        let mut state = state_arc.lock();

        match &mut state.status {
            SegmentStatus::Injecting { execs, .. } => {
                if let Some(exec) = execs.get_mut(&exec.id) {
                    match &mut *exec.lock() {
                        Execution::RaftLikeExecution(raft_like_exec) => {
                            info!("{segment} Raft-like error injection run failed: {error}");
                            raft_like_exec.outcome = Some(error.into());
                            self.incr_stat(ExecType::RaftLike, error.into());

                            *abort = false;
                        }
                        Execution::ParaHeteroExecution(para_hetero_exec) => {
                            info!("{segment} Parallel heterogeneous error injection run failed: {error}");
                            para_hetero_exec.outcome = Some(error.into());
                            self.incr_stat(ExecType::ParaHetero, error.into());

                            *abort = false;
                        }
                    }
                }
            }
            _ => (),
        }

        Ok(())
    }

    fn handle_checker_exec_fini(
        &self,
        segment: &Arc<Segment>,
        exec: &Arc<CheckerExecution>,
        ctx: HandlerContext,
    ) -> parallaft::error::Result<()> {
        let state_arc = self
            .segments
            .lock()
            .get_mut(&initial_segment_nr(segment, exec))
            .unwrap()
            .clone();

        let state = state_arc.lock();

        match &state.status {
            SegmentStatus::Injecting { execs, .. } => {
                if execs
                    .iter()
                    .all(|e| e.1.try_lock().and_then(|r| r.outcome()).is_some())
                {
                    info!("{segment} All error injection runs completed, unpinning segment");

                    let _segment_to_unpin = match execs.get(&exec.id) {
                        Some(e) => match &*e.lock() {
                            Execution::RaftLikeExecution(raft_like_exec) => {
                                raft_like_exec.initial_segment.clone()
                            }
                            _ => segment.clone(),
                        },
                        _ => segment.clone(),
                    };

                    // *segment_to_unpin.pinned.lock() = false;
                    ctx.check_coord.wakeup_main_worker();
                }
            }
            _ => (),
        }

        Ok(())
    }
}

impl SignalHandler for BisimErrorInjector {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> parallaft::error::Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        let checker = if let InferiorRefMut::Checker(checker) = context.child {
            checker
        } else {
            return Ok(SignalHandlerExitAction::NextHandler);
        };

        let mut segments = self.segments.lock();
        let state = segments.get_mut(&checker.initial_segment_nr());

        let state_arc = if let Some(state) = state {
            state.clone()
        } else {
            return Ok(SignalHandlerExitAction::NextHandler);
        };

        let mut state = state_arc.lock();

        match &state.status {
            SegmentStatus::Randomizing { irq: Some(irq), .. } => {
                if irq.is_interrupt(&checker.process.as_ref().unwrap().get_siginfo()?)? {
                    info!("{checker} Caught interrupt");

                    let exec_point = context
                        .check_coord
                        .dispatcher
                        .get_current_execution_point(&mut (*checker).into())?;

                    info!("{checker} Current execution point {exec_point:?}");

                    let registers_without_fault = checker.process().read_registers()?;

                    let registers_with_fault =
                        registers_without_fault.with_one_random_bit_flipped();

                    let raft_exec_id = EXEC_ID_RAFT_LIKE_BIT
                        | (checker.initial_segment_nr() & EXEC_ID_RAFT_LIKE_INITIAL_NR_MASK);

                    let raft_exec = checker.segment.new_checker_exec_with_id(raft_exec_id, true);
                    let para_hetero_exec = checker.segment.new_checker_exec(false);

                    state.status = SegmentStatus::Injecting {
                        exec_point,
                        registers_without_fault,
                        registers_with_fault,
                        execs: vec![
                            (
                                raft_exec.id,
                                Execution::RaftLikeExecution(RaftLikeExecution {
                                    in_initial_segment: true,
                                    initial_segment: checker.segment.clone(),
                                    segment: checker.segment.clone(),
                                    exec: raft_exec.clone(),
                                    outcome: None,
                                }),
                            ),
                            (
                                para_hetero_exec.id,
                                Execution::ParaHeteroExecution(ParaHeteroExecution {
                                    outcome: None,
                                }),
                            ),
                        ]
                        .into_iter()
                        .map(|(k, v)| (k, Arc::new(Mutex::new(v))))
                        .collect(),
                    };

                    context.check_coord.start_checker_worker_thread(
                        raft_exec,
                        checker.segment.clone(),
                        context.scope,
                    )?;

                    context.check_coord.start_checker_worker_thread(
                        para_hetero_exec,
                        checker.segment.clone(),
                        context.scope,
                    )?;

                    return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                        single_step: false,
                    });
                }
            }
            _ => (),
        }
        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ExecutionPointEventHandler for BisimErrorInjector {
    fn handle_freestanding_exec_point_reached(
        &self,
        _exec_point: &dyn ExecutionPoint,
        checker: &mut Checker<Stopped>,
    ) -> parallaft::error::Result<()> {
        let state_arc = self
            .segments
            .lock()
            .get_mut(&checker.initial_segment_nr())
            .unwrap()
            .clone();

        let state = state_arc.lock();

        match &state.status {
            SegmentStatus::Injecting {
                registers_with_fault,
                registers_without_fault,
                exec_point,
                execs,
                ..
            } => {
                assert!(execs.get(&checker.exec.id).is_some());

                info!("{checker} Injecting error at {exec_point}");
                let regs = checker.process().read_registers()?;
                assert_eq!(
                    regs.with_resume_flag_cleared(),
                    registers_without_fault.with_resume_flag_cleared()
                );

                // TODO: check exec_point == expected_exec_point
                checker
                    .process_mut()
                    .write_registers(*registers_with_fault)?;
            }
            _ => (),
        }
        Ok(())
    }
}

impl Module for BisimErrorInjector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut parallaft::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_signal_handler(self);
        subs.install_exec_point_event_handler(self);
    }
}

fn main() -> parallaft::error::Result<()> {
    pretty_env_logger::init();

    let cli = CliArgs::parse();
    let mut config: RelShellOptions = match cli.config {
        Some(path) => {
            let file = std::fs::File::open(path).expect("Failed to open config file");
            serde_yaml::from_reader(file).expect("Failed to parse config file")
        }
        None => RelShellOptions::default(),
    };

    config.checker_timeout_killer = true;
    config.exec_point_replay = true;
    config.check_coord_flags.ignore_miscmp = true;

    let _output = cli.output.map(|filename| {
        OpenOptions::new()
            .append(cli.append)
            .write(true)
            .create(true)
            .open(filename)
            .expect("Failed to open output file")
    });

    let stats = Arc::new(Mutex::new(HashMap::new()));

    config.extra_modules = vec![Box::new(BisimErrorInjector::new(stats.clone()))];

    parallaft::run(Command::new(cli.command).args(cli.args), config)?;

    info!("Result: {:#?}", &*stats.lock());

    Ok(())
}
