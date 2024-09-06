use std::{
    collections::HashMap,
    path::PathBuf,
    process::Command,
    sync::Arc,
    thread::sleep,
    time::{Duration, Instant},
};

use clap::Parser;
use git_version::git_version;
use log::{error, info};
use nix::sys::signal::Signal;
use parking_lot::Mutex;
use reldrv::{
    dispatcher::Module,
    error::{Error, UnexpectedEventReason},
    events::{
        process_lifetime::HandlerContext,
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{registers::RegisterAccess, state::Stopped},
    types::{
        checker::{CheckFailReason, CheckerStatus},
        exit_reason::ExitReason,
        process_id::Checker,
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

    /// Don't actually inject errors
    #[arg(short, long)]
    dry_run: bool,

    command: String,
    args: Vec<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
enum ResultKind {
    Pass,
    ControlFlowViolation, // excess syscalls/traps/etc.
    EventMismatch,        // syscall/trap/etc. mismatch
    MemoryMapMismatch,
    MemoryMismatch,
    RegisterMismatch,
    UnexpectedSegmentationFault,
    UnexpectedIllegalInstruction,
    UnexpectedBusError,
    OtherFailure,
}

#[derive(Debug, PartialEq, Eq)]
enum SegmentStatus {
    Training { started: Instant },
    Injecting { length: Duration },
}

#[derive(Debug)]
struct SegmentState {
    counts: HashMap<ResultKind, u64>,
    total: u64,
    injected: u64,
    status: SegmentStatus,
}

impl SegmentState {
    fn new() -> Self {
        Self {
            counts: HashMap::new(),
            total: 0,
            injected: 0,
            status: SegmentStatus::Training {
                started: Instant::now(),
            },
        }
    }
}

#[derive(Debug)]
struct State {
    segments: HashMap<SegmentId, SegmentState>,
}

impl State {
    fn new() -> Self {
        Self {
            segments: HashMap::new(),
        }
    }
}

struct ErrorInjector {
    state: Arc<Mutex<State>>,
    iters_per_segment: u64,
    dry_run: bool,
}

impl ErrorInjector {
    const SIGVAL_INJECT_ERROR: usize = 0xc8a0820d360efe8e;

    fn new(iters_per_segment: u64, dry_run: bool, state: Arc<Mutex<State>>) -> Self {
        Self {
            state,
            iters_per_segment,
            dry_run,
        }
    }
}

impl SegmentEventHandler for ErrorInjector {
    fn handle_segment_ready(
        &self,
        checker: &mut Checker<Stopped>,
        ctx: HandlerContext,
    ) -> reldrv::error::Result<()> {
        let mut state = self.state.lock();
        let segment_state = state
            .segments
            .entry(checker.segment.nr)
            .or_insert_with(SegmentState::new);

        match &segment_state.status {
            SegmentStatus::Training { .. } => (),
            SegmentStatus::Injecting { length } => {
                let length = *length;
                let process = checker.process().unowned_copy();
                let segment = checker.segment.clone();
                ctx.scope.spawn(move || {
                    let duration = length.mul_f64(1.1 * rand::random::<f64>());
                    info!("{} Sleeping for {:?} before injection", segment, duration);
                    sleep(duration);
                    process.sigqueue(Self::SIGVAL_INJECT_ERROR).ok();
                });

                segment_state.total += 1;
            }
        };

        Ok(())
    }

    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
        check_fail_reason: &Option<CheckFailReason>,
        _ctx: HandlerContext,
    ) -> reldrv::error::Result<()> {
        let mut state = self.state.lock();
        let segment_state = &mut state.segments.get_mut(&checker.segment.nr).unwrap();

        if let SegmentStatus::Training { started } = segment_state.status {
            segment_state.status = SegmentStatus::Injecting {
                length: started.elapsed(),
            };
            *checker.segment.as_ref().pinned.lock() = true;

            return Ok(());
        }

        let segment_counts = &mut segment_state.counts;

        if let Some(reason) = check_fail_reason {
            let kind = match reason {
                CheckFailReason::MemoryMapMismatch => ResultKind::MemoryMapMismatch,
                CheckFailReason::MemoryMismatch => ResultKind::MemoryMismatch,
                CheckFailReason::RegisterMismatch => ResultKind::RegisterMismatch,
            };

            *segment_counts.entry(kind).or_default() += 1;
        } else {
            *segment_counts.entry(ResultKind::Pass).or_default() += 1;
        }

        if segment_state.injected >= self.iters_per_segment {
            *checker.segment.pinned.lock() = false;
        }

        Ok(())
    }

    fn handle_segment_checker_error(
        &self,
        segment: &Arc<Segment>,
        error: &Error,
        abort: &mut bool,
        _ctx: HandlerContext,
    ) -> reldrv::error::Result<()> {
        let mut state = self.state.lock();

        let segment_state = &mut state.segments.get_mut(&segment.nr).unwrap();

        if let SegmentStatus::Training { .. } = segment_state.status {
            return Ok(());
        }

        let kind = match error {
            Error::UnexpectedEvent(UnexpectedEventReason::Excess) => {
                ResultKind::ControlFlowViolation
            }
            Error::UnexpectedEvent(_) => ResultKind::EventMismatch,
            Error::UnexpectedCheckerExitReason(reason) => match reason {
                ExitReason::Signalled(Signal::SIGSEGV) => ResultKind::UnexpectedSegmentationFault,
                ExitReason::Signalled(Signal::SIGILL) => ResultKind::UnexpectedIllegalInstruction,
                ExitReason::Signalled(Signal::SIGBUS) => ResultKind::UnexpectedBusError,
                _ => ResultKind::OtherFailure,
            },
            _ => ResultKind::OtherFailure,
        };

        if kind == ResultKind::OtherFailure {
            error!("{} Unexpected error: {:?}", segment, error);
        }

        *segment_state.counts.entry(kind).or_default() += 1;

        if segment_state.injected >= self.iters_per_segment {
            *segment.pinned.lock() = false;
            segment.checker_status.lock().assume_checked();
        }

        *abort = false; // don't abort the main thread

        Ok(())
    }

    fn handle_checker_worker_fini(
        &self,
        segment: &Arc<Segment>,
        ctx: HandlerContext,
    ) -> reldrv::error::Result<()> {
        if *segment.pinned.lock() {
            info!("{} Restarting checker thread for error injection", segment);
            ctx.check_coord
                .start_checker_worker_thread(segment.clone(), ctx.scope)?;
        }
        Ok(())
    }
}

impl SignalHandler for ErrorInjector {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        mut context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> reldrv::error::Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGUSR1
            || context.child.process().get_sigval()? != Some(Self::SIGVAL_INJECT_ERROR)
        {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        if !matches!(
            &*context.child.segment().unwrap().checker_status.lock(),
            CheckerStatus::Executing { .. }
        ) {
            return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                single_step: false,
            });
        }

        if self.dry_run {
            info!("{} Dry run: not injecting error", context.child);
        } else {
            info!("{} Injecting error", context.child);
            context
                .process_mut()
                .modify_registers_with(|r| r.with_one_random_bit_flipped())?;
        }

        self.state
            .lock()
            .segments
            .get_mut(&context.child.segment().unwrap().nr)
            .unwrap()
            .injected += 1;

        Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step: false })
    }
}

impl Module for ErrorInjector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut reldrv::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_signal_handler(self);
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

    let state = Arc::new(Mutex::new(State::new()));

    config.extra_modules = vec![Box::new(ErrorInjector::new(
        cli.iters_per_segment,
        cli.dry_run,
        state.clone(),
    ))];

    config.check_coord_flags.ignore_miscmp = true;

    reldrv::run(Command::new(cli.command).args(cli.args), config)?;

    dbg!(&*state.lock());

    Ok(())
}
