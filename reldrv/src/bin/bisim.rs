use core::panic;
use std::{collections::HashMap, fs::OpenOptions, path::PathBuf, process::Command, sync::Arc};

use clap::Parser;
use derivative::Derivative;
use git_version::git_version;
use log::info;
use nix::sys::signal::Signal;
use parking_lot::Mutex;
use perf_event::events::Hardware;
use reldrv::{
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
        state::{Running, Stopped},
    },
    types::{
        checker_exec::CheckerExecution,
        execution_point::{ExecutionPoint, ExecutionPointOwner},
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

#[derive(Parser, Debug)]
#[command(version = git_version!())]
struct CliArgs {
    /// Config file to use
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Number of error injection iterations per segment
    #[arg(short = 'n', long, default_value = "10")]
    iters_per_segment: u64,

    /// Ignore missed injections
    #[arg(short = 'i', long)]
    ignore_missed: bool,

    /// Don't actually inject errors
    #[arg(short, long)]
    dry_run: bool,

    /// Start injection on or newer than the specified segment number
    #[arg(short, long)]
    since: Option<SegmentId>,

    /// Stop injection on or older than the specified segment number
    #[arg(short, long)]
    until: Option<SegmentId>,

    /// Result output filename
    #[arg(short, long)]
    output: Option<PathBuf>,

    /// Append instead of rewriting to the output file
    #[arg(long)]
    append: bool,

    command: String,
    args: Vec<String>,
}

#[derive(Debug)]
struct RaftLikeExecution {
    segment: Arc<Segment>,
    exec: Arc<CheckerExecution>,
}

#[derive(Debug)]
struct ParaHeteroExecution {
    segment: Arc<Segment>,
    exec: Arc<CheckerExecution>,
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
        registers_with_fault: Registers,
        raft_like_exec: Option<RaftLikeExecution>,
        para_hetero_exec: Option<ParaHeteroExecution>,
    },
    Done,
}

#[derive(Debug)]
struct SegmentState {
    nr: SegmentId,
    status: SegmentStatus,
}

impl SegmentState {
    fn new(nr: SegmentId) -> Self {
        Self {
            nr,
            status: SegmentStatus::New,
        }
    }
}

struct BisimErrorInjector {
    segments: Mutex<HashMap<SegmentId, SegmentState>>,
}

impl BisimErrorInjector {
    fn new() -> Self {
        Self {
            segments: Mutex::new(HashMap::new()),
        }
    }
}

impl SegmentEventHandler for BisimErrorInjector {
    fn handle_segment_created(&self, main: &mut Main<Running>) -> reldrv::error::Result<()> {
        if let Some(segment) = &main.segment {
            self.segments
                .lock()
                .insert(segment.nr, SegmentState::new(segment.nr));
        }

        Ok(())
    }

    fn handle_segment_filled(&self, main: &mut Main<Running>) -> reldrv::error::Result<()> {
        // start checker
        Ok(())
    }

    fn handle_checker_exec_ready(
        &self,
        checker: &mut Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> reldrv::error::Result<()> {
        let mut segments = self.segments.lock();
        let state = segments.get_mut(&checker.segment.nr).unwrap();

        match &mut state.status {
            SegmentStatus::New => {
                info!("{checker} Starting training run");
                state.status = SegmentStatus::Training {
                    cycle_counter: GenericHardwareEventCounter::new(
                        Hardware::CPU_CYCLES,
                        reldrv::types::perf_counter::symbolic_events::expr::Target::Pid(
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
            SegmentStatus::Injecting { exec_point, .. } => {
                info!("{checker} Preparing execution point for error injection");
                exec_point.prepare(
                    &checker.segment,
                    &checker.exec,
                    ExecutionPointOwner::Freestanding,
                )?;
            }
            SegmentStatus::Done => todo!(),
        }

        Ok(())
    }

    fn handle_checker_exec_completed(
        &self,
        checker: &mut Checker<Stopped>,
        ctx: HandlerContext,
    ) -> reldrv::error::Result<()> {
        let mut segments = self.segments.lock();
        let state = segments.get_mut(&checker.segment.nr).unwrap();

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
            SegmentStatus::Injecting { .. } => {}
            SegmentStatus::Done => todo!(),
        }

        Ok(())
    }
}

impl SignalHandler for BisimErrorInjector {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> reldrv::error::Result<SignalHandlerExitAction>
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
        let state = segments.get_mut(&checker.segment.nr).unwrap();

        match &state.status {
            SegmentStatus::Randomizing { irq: Some(irq), .. } => {
                if irq.is_interrupt(&checker.process.as_ref().unwrap().get_siginfo()?)? {
                    info!("{checker} Caught interrupt");

                    let exec_point = context
                        .check_coord
                        .dispatcher
                        .get_current_execution_point(&mut (*checker).into())?;

                    info!("{checker} Current execution point {exec_point:?}");

                    let registers_with_fault = checker
                        .process()
                        .read_registers()?
                        .with_one_random_bit_flipped();

                    state.status = SegmentStatus::Injecting {
                        exec_point,
                        registers_with_fault,
                        raft_like_exec: Some(RaftLikeExecution {
                            segment: checker.segment.clone(),
                            exec: checker.segment.new_checker_exec(true),
                        }),
                        para_hetero_exec: Some(ParaHeteroExecution {
                            segment: checker.segment.clone(),
                            exec: checker.segment.new_checker_exec(false),
                        }),
                    };

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
        exec_point: &dyn ExecutionPoint,
        checker: &mut Checker<Stopped>,
    ) -> reldrv::error::Result<()> {
        let mut segments = self.segments.lock();
        let state = segments.get_mut(&checker.segment.nr).unwrap();

        match &state.status {
            SegmentStatus::Injecting {
                registers_with_fault,
                ..
            } => {
                info!("{checker} Injecting error at {exec_point}");
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

fn main() -> reldrv::error::Result<()> {
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

    let output = cli.output.map(|filename| {
        OpenOptions::new()
            .append(cli.append)
            .write(true)
            .create(true)
            .open(filename)
            .expect("Failed to open output file")
    });

    // let state = Arc::new(Mutex::new(State::new()));

    // config.extra_modules = vec![Box::new(ErrorInjector::new(
    //     cli.iters_per_segment,
    //     cli.dry_run,
    //     cli.ignore_missed,
    //     cli.since,
    //     cli.until,
    //     state.clone(),
    //     output,
    // ))];

    config.check_coord_flags.ignore_miscmp = true;

    reldrv::run(Command::new(cli.command).args(cli.args), config)?;

    Ok(())
}
