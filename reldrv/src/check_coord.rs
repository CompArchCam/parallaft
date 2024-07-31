use std::collections::HashMap;
use std::ops::{Deref, DerefMut};
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use std::sync::Arc;
use std::thread::{park, Scope, Thread};

use derive_builder::Builder;
use log::{debug, error, info, warn};

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};

use reverie_syscalls::{Displayable, Syscall, SyscallArgs, SyscallInfo};
use scopeguard::defer;

use crate::dirty_page_trackers::ExtraWritableRangesProvider;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result, UnexpectedEventReason};
use crate::events::hctx;
use crate::events::module_lifetime::ModuleLifetimeHook;
use crate::events::process_lifetime::{pctx, ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::events::syscall::{
    CustomSyscallHandler, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler, SyscallHandlerExitAction,
};
use crate::events::{
    segment::SegmentEventHandler,
    signal::{SignalHandler, SignalHandlerExitAction},
};
use crate::exec_point_providers::ExecutionPointProvider;
use crate::process::dirty_pages::IgnoredPagesProvider;
use crate::process::registers::RegisterAccess;
use crate::process::{OwnedProcess, Process};
use crate::statistics::timing::{self, Tracer};
use crate::syscall_handlers::{SYSNO_CHECKPOINT_FINI, SYSNO_CHECKPOINT_TAKE};
use crate::throttlers::Throttler;
use crate::types::chains::SegmentChains;
use crate::types::checker::CheckerStatus;
use crate::types::checkpoint::{Checkpoint, CheckpointCaller};
use crate::types::exit_reason::ExitReason;
use crate::types::process_id::{Checker, Inferior, Main};
use crate::types::segment::{Segment, SegmentId, SegmentStatus};
use crate::types::segment_record::manual_checkpoint::ManualCheckpointRequest;
use crate::types::segment_record::saved_memory::SavedMemory;
use crate::types::segment_record::saved_syscall::{
    SavedIncompleteSyscallKind, SavedSyscallKind, SyscallExitAction,
};

#[derive(Debug)]
struct Worker {
    thread: Thread,
}

pub struct CheckCoordinator<'disp, 'modules, 'tracer> {
    pub segments: Arc<RwLock<SegmentChains>>,
    pub main: Process, // TODO: remove this
    pub epoch: AtomicU32,
    options: CheckCoordinatorOptions,
    pub dispatcher: &'disp Dispatcher<'disp, 'modules>,
    workers: Mutex<HashMap<SegmentId, Worker>>,
    main_thread: Thread,
    aborting: AtomicBool,
    tracer: &'tracer Tracer,
}

#[derive(Debug, Default, Clone, Builder)]
#[builder(default)]
pub struct CheckCoordinatorOptions {
    /// Don't compare state between a completed checker and the checkpoint. Assume their state matches.
    pub no_state_cmp: bool,
    /// Don't execute checkers.
    pub no_checker_exec: bool,
    /// Don't fork the main app into checkers or checkpoints.
    pub no_fork: bool,
    /// Ignore state mismatches.
    pub ignore_miscmp: bool,

    pub enable_async_events: bool,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyscallType {
    Standard(Syscall),
    Custom(usize, SyscallArgs),
}

impl<'disp, 'modules, 'tracer> CheckCoordinator<'disp, 'modules, 'tracer>
where
    'modules: 'disp,
{
    pub fn new(
        main: Process,
        options: CheckCoordinatorOptions,
        dispatcher: &'disp Dispatcher<'disp, 'modules>,
        tracer: &'tracer Tracer,
    ) -> Self {
        Self {
            segments: Arc::new(RwLock::new(SegmentChains::new())),
            main,
            epoch: AtomicU32::new(0),
            options,
            dispatcher,
            workers: Mutex::new(HashMap::new()),
            main_thread: std::thread::current(),
            aborting: AtomicBool::new(false),
            tracer,
        }
    }

    fn run_event_loop<'s, 'scope, 'env>(
        &'s self,
        mut child: Inferior,
        mut ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<ExitReason>
    where
        's: 'scope + 'disp,
    {
        info!("{child} Ready");

        let wall_time_event;

        // Dispatch init
        match &mut child {
            Inferior::Main(main) => {
                self.dispatcher
                    .handle_main_init(pctx(&mut main.process, self, scope))?;
                wall_time_event = timing::Event::MainWall;
            }
            Inferior::Checker(checker) => {
                self.dispatcher
                    .handle_checker_init(pctx(&mut checker.process, self, scope))?;
                wall_time_event = timing::Event::CheckerWall;
            }
        }

        let wall_time_tracer = self.tracer.trace(wall_time_event);
        child.process().resume()?;

        // Main loop
        let exit_reason = loop {
            let status = match child.process().waitpid() {
                Ok(s) => s,
                Err(Errno::ECHILD) => break ExitReason::UnexpectedlyDies,
                Err(e) => panic!("waitpid error {e:?}"),
            };

            if child.is_main() && self.aborting.load(Ordering::SeqCst) {
                break ExitReason::Crashed(Error::Cancelled);
            }

            match status {
                WaitStatus::Exited(_, status) => {
                    if child.is_main() {
                        info!("{child} Exit: {status}");
                    }
                    break ExitReason::NormalExit(status);
                }
                WaitStatus::Signaled(_, sig, _) => {
                    if child.is_checker() && sig == Signal::SIGKILL {
                        break ExitReason::NormalExit(0);
                    }

                    info!("{child} Killed: {sig}");
                    break ExitReason::Signalled(sig);
                }
                WaitStatus::Stopped(_, sig) => {
                    self.handle_signal(&mut child, sig, scope)?;
                }
                WaitStatus::PtraceSyscall(_) => {
                    // Tell if it is a syscall entry or exit
                    let is_syscall_entry = child.process().syscall_dir()?.is_entry();
                    assert_eq!(is_syscall_entry, ongoing_syscall.is_none());

                    let regs = child.process().read_registers()?;

                    match ongoing_syscall {
                        None => {
                            // Syscall entry
                            if let Some(sysno) = regs.sysno() {
                                let syscall = Syscall::from_raw(sysno, regs.syscall_args());
                                // Standard syscall entry
                                self.handle_syscall_entry(&mut child, syscall, scope)?;
                                ongoing_syscall = Some(SyscallType::Standard(syscall));
                            } else {
                                // Custom syscall entry
                                self.handle_custom_syscall_entry(
                                    &mut child,
                                    regs.sysno_raw(),
                                    regs.syscall_args(),
                                    scope,
                                )?;

                                ongoing_syscall = Some(SyscallType::Custom(
                                    regs.sysno_raw(),
                                    regs.syscall_args(),
                                ));
                            }
                        }
                        Some(SyscallType::Standard(syscall)) => {
                            // Standard syscall exit
                            self.handle_syscall_exit(
                                &mut child,
                                syscall,
                                regs.syscall_ret_val(),
                                scope,
                            )?;

                            ongoing_syscall = None;
                        }
                        Some(SyscallType::Custom(sysno, args)) => {
                            // Custom syscall exit
                            self.handle_custom_syscall_exit(
                                &mut child,
                                sysno,
                                args,
                                regs.syscall_ret_val(),
                                scope,
                            )?;

                            ongoing_syscall = None;
                        }
                    }
                }
                WaitStatus::StillAlive => continue,
                ws => unreachable!("{ws:?}"),
            }
        };

        wall_time_tracer.end();

        // Dispatch fini and extra checks on segment status
        match &mut child {
            Inferior::Main(main) => {
                // if self
                //     .segments
                //     .read_recursive()
                //     .list
                //     .iter()
                //     .any(|x| matches!(&*x.status.lock(), SegmentStatus::Filling))
                // {
                //     info!("Main crashed without marking segment status as crashed");
                //     return Ok(ExitReason::Crashed(Error));
                // }

                self.dispatcher.handle_main_fini(
                    match exit_reason {
                        ExitReason::NormalExit(ret) => ret,
                        _ => -1,
                    }, /* todo */
                    pctx(&mut main.process, self, scope),
                )?;
            }
            Inferior::Checker(checker) => {
                assert!(checker.segment.checker_status.lock().is_finished());

                self.dispatcher.handle_checker_fini(
                    None, /* todo */
                    pctx(&mut checker.process, self, scope),
                )?
            }
        }

        info!("{child} Done");

        Ok(exit_reason)
    }

    fn wait_until_unthrottled(
        &self,
        main: &mut Main,
        throttler: &(dyn Throttler + Sync),
        segments: &mut RwLockUpgradableReadGuard<SegmentChains>, // TODO: changeme
    ) {
        loop {
            RwLockUpgradableReadGuard::unlocked(segments, || {
                park();
            });

            if self.aborting.load(Ordering::SeqCst) {
                break;
            }

            if throttler.should_unthrottle(main, segments, self) {
                info!("Unthrottled");
                break;
            }
            if segments.nr_live_segments() <= 1 {
                panic!(
                    "Deadlock detected: unthrottle not called after the number of live segments reaching one"
                );
            }
        }

        if let Some(segment) = &main.segment {
            let mut status = segment.status.lock();
            match &mut *status {
                SegmentStatus::Filling { blocked, .. } => *blocked = false,
                _ => panic!("Unexpected main status"),
            }
        }
    }

    /// Take a checkpoint of the main inferior. When taking this checkpoint, the
    /// main inferior must not execute after the last saved event.
    fn take_main_checkpoint<'s, 'scope, 'env>(
        &'s self,
        main: &mut Main,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let checkpointing_tracer = self.tracer.trace(timing::Event::MainCheckpointing);
        info!("{main} Checkpoint");
        if self.options.no_fork {
            main.process.resume()?;
            return Ok(());
        }

        let mut segments = self.segments.upgradable_read();
        let in_chain = segments.in_chain();

        if !in_chain && is_finishing {
            info!("{main} No-op checkpoint_fini");
            main.process.resume()?;
            return Ok(());
        }

        let epoch_local = self.epoch.fetch_add(1, Ordering::SeqCst);

        let forking_tracer = self.tracer.trace(timing::Event::MainForking);
        let reference = main.process.fork(restart_old_syscall, true)?;
        forking_tracer.end();

        let dirty_page_tracking_tracer = self.tracer.trace(timing::Event::MainDirtyPageTracking);
        self.dispatcher.handle_checkpoint_created_pre(main)?;
        dirty_page_tracking_tracer.end();

        let throttler = if in_chain {
            self.dispatcher.dispatch_throttle(main, &segments, self)
        } else {
            None
        };

        main.process.resume()?;
        checkpointing_tracer.end();

        let checkpoint = Checkpoint::new(epoch_local, reference, caller);

        match (in_chain, is_finishing) {
            (false, false) => {
                // Start of the segment chain
                info!("{main} Protection on");
            }
            (true, false) => {
                // Middle of the segment chain
            }
            (true, true) => {
                // End of the segment chain
                info!("{main} Protection off");
            }
            _ => unreachable!(),
        }

        debug!("{main} New checkpoint: {:#?}", checkpoint);
        segments.with_upgraded(|segments_mut| {
            self.add_checkpoint(
                main,
                segments_mut,
                checkpoint,
                is_finishing,
                ongoing_syscall,
                scope,
            )
        })?;

        if let Some(throttler) = throttler {
            let throttling_tracer = self.tracer.trace(timing::Event::MainThrottling);
            if let Some(segment) = main.segment.as_ref() {
                match &mut *segment.status.lock() {
                    SegmentStatus::Filling { blocked, .. } => *blocked = true,
                    _ => panic!("Unexpected main state"),
                }
            }

            self.wait_until_unthrottled(main, throttler, &mut segments);
            throttling_tracer.end();
        }

        Ok(())
    }

    fn take_checker_checkpoint<'s, 'scope, 'env>(&'s self, checker: &mut Checker) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let checker_comparing_tracer = self.tracer.trace(timing::Event::CheckerComparing);

        info!("{checker} Checkpoint");

        self.dispatcher.handle_segment_completed(checker)?;

        let check_fail_reason;

        if self.options.no_state_cmp {
            check_fail_reason = None;
            checker.segment.checker_status.lock().assume_checked();
        } else {
            check_fail_reason = checker.segment.clone().check(
                checker,
                &self.dispatcher.get_ignored_pages(),
                &self.dispatcher.get_extra_writable_ranges(),
                self.dispatcher,
                self.dispatcher,
            )?;

            match check_fail_reason {
                Some(reason) => {
                    if self.options.ignore_miscmp {
                        warn!("{checker} Check failed, reason {reason:?}, ignoring");
                    } else {
                        self.aborting.store(true, Ordering::SeqCst);
                        error!("{checker} Check failed, reason {reason:?}, terminating");
                    }
                }
                None => info!("{checker} Check passed"),
            }
        }

        self.dispatcher
            .handle_segment_checked(checker, &check_fail_reason)?;

        let mut segments = self.segments.write();
        self.cleanup_committed_segments(&mut segments, true)?;
        drop(segments);

        checker_comparing_tracer.end();

        checker.process.kill()?;

        Ok(())
    }

    /// Handle checkpoint request from the target
    fn take_checkpoint<'s, 'scope, 'env>(
        &'s self,
        child: &mut Inferior,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        match child {
            Inferior::Main(main) => self.take_main_checkpoint(
                main,
                is_finishing,
                restart_old_syscall,
                caller,
                ongoing_syscall,
                scope,
            ),
            Inferior::Checker(checker) => self.take_checker_checkpoint(checker),
        }
    }

    fn cleanup_committed_segments(
        &self,
        segments: &mut SegmentChains,
        keep_crashed_segments: bool,
    ) -> Result<()> {
        segments.cleanup_committed_segments(
            !self.options.ignore_miscmp,
            keep_crashed_segments,
            |segment| self.dispatcher.handle_segment_removed(&segment),
        )?;

        self.main_thread.unpark();

        Ok(())
    }

    pub fn main_work<'s, 'scope, 'env>(
        &'s self,
        process: OwnedProcess,
        scope: &'scope Scope<'scope, 'env>,
    ) -> ExitReason
    where
        's: 'scope + 'disp,
    {
        defer! {
            if let Some(last_segment) = self.segments.read().last_segment() {
                if !last_segment.is_main_finished() {
                    error!("Main worker crashed without marking segment as finished");
                    last_segment.mark_as_crashed();
                }
            }

            self.dispatcher.fini(scope).unwrap();
        }
        (|| {
            self.dispatcher.init(scope)?;

            let mut exit_reason = match self.run_event_loop(
                Inferior::Main(Main {
                    process,
                    segment: None,
                }),
                None,
                scope,
            ) {
                Ok(exit_reason) => exit_reason,
                Err(err) => {
                    error!("Main worker crashed with error: {:?}", err);

                    if let Some(last_segment) = self.segments.read().last_segment() {
                        last_segment.mark_as_crashed();
                    }

                    return Err(err);
                }
            };

            self.wait_until_and_handle_completion(scope)?;

            exit_reason = self
                .segments
                .read()
                .collect_results()
                .unwrap_or(exit_reason);

            Ok(exit_reason)
        })()
        .unwrap_or_else(|err| ExitReason::Crashed(err))
    }

    fn checker_work<'s, 'scope, 'env>(
        &'s self,
        segment: Arc<Segment>,
        ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let checker_starting_tracer = self.tracer.trace(timing::Event::CheckerStarting);

        let checker_forking_tracer = self.tracer.trace(timing::Event::CheckerForking);
        let checker_process = segment.start_checker()?;
        checker_forking_tracer.end();

        segment.record.wait_for_initial_event()?;

        if !self.options.no_checker_exec {
            let checker_ready_hook_tracer = self.tracer.trace(timing::Event::CheckerReadyHook);

            let mut checker = Checker {
                process: checker_process,
                segment: segment.clone(),
            };

            self.dispatcher.handle_segment_ready(&mut checker)?;
            checker_ready_hook_tracer.end();

            self.run_event_loop(Inferior::Checker(checker), ongoing_syscall, scope)?;
        } else {
            segment.checker_status.lock().assume_checked();
        }
        checker_starting_tracer.end();

        Ok(())
    }

    fn add_checkpoint<'s, 'scope, 'env>(
        &'s self,
        main: &mut Main,
        segments: &mut SegmentChains,
        checkpoint: Checkpoint,
        is_finishing: bool,
        ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let result = segments.add_checkpoint(
            checkpoint,
            is_finishing,
            main.process.pid,
            self.options.enable_async_events,
        );

        if let Some(last_segment) = result.last_segment {
            self.dispatcher.handle_segment_filled(main)?;

            self.workers
                .lock()
                .get(&last_segment.nr)
                .map(|x| x.thread.unpark());
        }

        main.segment = result.new_segment.clone();

        if let Some(new_segment) = result.new_segment {
            self.dispatcher.handle_segment_created(main)?;

            let segment_nr = new_segment.nr;

            let mut workers = self.workers.lock();

            let jh = std::thread::Builder::new()
                .name(format!("checker-{}", new_segment.nr))
                .spawn_scoped(scope, move || {
                    let ret = catch_unwind(AssertUnwindSafe(|| {
                        self.checker_work(new_segment.clone(), ongoing_syscall, scope)
                    }));

                    let abort;

                    match ret {
                        Err(_) => {
                            error!("Checker worker panicked");
                            *new_segment.checker_status.lock() =
                                CheckerStatus::Crashed(Error::Panic);
                            abort = true;
                        }
                        Ok(Err(e)) => {
                            error!("Checker worker failed with error: {e:?}");
                            *new_segment.checker_status.lock() = CheckerStatus::Crashed(e);
                            abort = true;
                        }
                        Ok(Ok(())) => {
                            let mut checker_status = new_segment.checker_status.lock();

                            if !checker_status.is_finished() {
                                info!("Checker not marked finished, assuming it is cancelled");
                                *checker_status = CheckerStatus::Crashed(Error::Cancelled);
                            }

                            abort = false;
                        }
                    }

                    if abort {
                        self.aborting.store(true, Ordering::SeqCst);
                        self.main_thread.unpark();
                    }
                })
                .unwrap();

            workers.insert(
                segment_nr,
                Worker {
                    thread: jh.thread().clone(),
                },
            );
        }

        if is_finishing {
            self.dispatcher.handle_segment_chain_closed(main)?;
        }

        self.cleanup_committed_segments(segments, true)?;

        Ok(())
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Check if all segments have finished.
    pub fn is_all_finished(&self) -> bool {
        self.segments
            .read()
            .list
            .iter()
            .all(|segment| segment.is_both_finished())
    }

    /// Wait until all segments are checked, and call `disp.handle_all_fini()`. Needs to be called from the main thread
    pub fn wait_until_and_handle_completion<'s, 'scope>(
        &'s self,
        scope: &'scope Scope<'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        self.cleanup_committed_segments(&mut self.segments.write(), true)?;

        while !self.is_all_finished() && !self.aborting.load(Ordering::SeqCst) {
            park();
        }

        self.dispatcher
            .handle_all_fini(ProcessLifetimeHookContext {
                process: &self.main,
                check_coord: self,
                scope,
            })?; // TODO

        // Cancel all checkers
        self.segments.read().mark_all_filling_segments_as_crashed();
        let workers = self.workers.lock();
        for worker in workers.values() {
            worker.thread.unpark();
        }

        Ok(())
    }

    pub fn handle_syscall_entry<'s, 'scope, 'env>(
        &'s self,
        child: &mut Inferior,
        syscall: Syscall,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let tracing_event = match child {
            Inferior::Main(_) => timing::Event::MainSyscallEntryHandling,
            Inferior::Checker(_) => timing::Event::CheckerSyscallEntryHandling,
        };

        let syscall_entry_handling_tracer = self.tracer.trace(tracing_event);

        let mut skip_ptrace_syscall = false;

        info!(
            "{child} Syscall: {:}",
            syscall.display(child.process().deref())
        );

        if matches!(
            self.dispatcher
                .handle_standard_syscall_entry(&syscall, hctx(&mut child.into(), self, scope))?,
            SyscallHandlerExitAction::ContinueInferior
        ) {
            child.process().resume()?;
            return Ok(());
        }

        match child {
            Inferior::Main(main) => {
                // Main syscall entry
                if let Some(segment) = &main.segment {
                    let segment = segment.clone();
                    // Main syscall entry, inside protection zone

                    let result = self.dispatcher.handle_standard_syscall_entry_main(
                        &syscall,
                        hctx(&mut main.into(), self, scope),
                    )?;

                    match result {
                        StandardSyscallEntryMainHandlerExitAction::NextHandler => {
                            panic!("Unhandled syscall entry")
                        }
                        StandardSyscallEntryMainHandlerExitAction::StoreSyscall(
                            saved_incomplete_syscall,
                        ) => {
                            segment
                                .record
                                .push_incomplete_syscall(saved_incomplete_syscall);
                        }
                        StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                            saved_incomplete_syscall,
                        ) => {
                            segment
                                .record
                                .push_event(saved_incomplete_syscall, true, &segment)?;

                            syscall_entry_handling_tracer.end();

                            self.take_main_checkpoint(
                                main,
                                true,
                                true,
                                CheckpointCaller::Shell,
                                Some(SyscallType::Standard(syscall)),
                                scope,
                            )?;

                            skip_ptrace_syscall = true;
                        }
                    }
                }
            }
            Inferior::Checker(checker) => {
                // Checker syscall entry
                let result = self.dispatcher.handle_standard_syscall_entry_checker(
                    &syscall,
                    hctx(&mut checker.into(), self, scope),
                )?;

                match result {
                    StandardSyscallEntryCheckerHandlerExitAction::NextHandler => {
                        panic!("Unhandled syscall exit")
                    }
                    StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior => (),
                    StandardSyscallEntryCheckerHandlerExitAction::Checkpoint => {
                        let incomplete_syscall = checker.segment.record.pop_incomplete_syscall()?;

                        assert!(incomplete_syscall.is_last_event);

                        syscall_entry_handling_tracer.end();

                        self.take_checker_checkpoint(checker)?;

                        skip_ptrace_syscall = true;
                    }
                }
            }
        }

        if !skip_ptrace_syscall {
            child.process().resume()?;
        }

        Ok(())
    }

    pub fn handle_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        child: &mut Inferior,
        last_syscall: Syscall,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        debug!("{child} Syscall: ... = {ret_val}");

        let tracing_event = match child {
            Inferior::Main(_) => timing::Event::MainSyscallExitHandling,
            Inferior::Checker(_) => timing::Event::CheckerSyscallExitHandling,
        };

        let syscall_exit_handling_tracer = self.tracer.trace(tracing_event);

        let mut skip_ptrace_syscall = false;

        if self.dispatcher.handle_standard_syscall_exit(
            ret_val,
            &last_syscall,
            hctx(&mut child.into(), self, scope),
        )? == SyscallHandlerExitAction::ContinueInferior
        {
            child.process().resume()?;
            return Ok(());
        }

        match child {
            Inferior::Main(main) => {
                if let Some(segment) = &main.segment {
                    let segment = segment.clone();
                    // Main syscall entry, inside protection zone

                    let saved_incomplete_syscall = segment
                        .record
                        .take_incomplete_syscall()
                        .expect("Unexpected ptrace event");

                    let exit_action = saved_incomplete_syscall.exit_action;

                    let saved_syscall = match exit_action {
                        SyscallExitAction::ReplayEffects => {
                            // TODO: move this to syscall_handlers/record_replay.rs

                            // store memory contents that are potentially written during the syscall
                            let mem_written = match &saved_incomplete_syscall.kind {
                                SavedIncompleteSyscallKind::WithMemoryEffects {
                                    mem_written_ranges,
                                    ..
                                } => SavedMemory::save(main.process.deref(), mem_written_ranges)?,
                                _ => panic!(),
                            };

                            saved_incomplete_syscall.with_return_value(ret_val, Some(mem_written))
                        }
                        SyscallExitAction::ReplicateSyscall => {
                            saved_incomplete_syscall.with_return_value(ret_val, None)
                        }
                        SyscallExitAction::Custom => {
                            let result = self.dispatcher.handle_standard_syscall_exit_main(
                                ret_val,
                                &saved_incomplete_syscall,
                                hctx(&mut main.into(), self, scope),
                            )?;

                            assert!(
                                !matches!(result, SyscallHandlerExitAction::NextHandler),
                                "Unhandled custom syscall during syscall exit"
                            );

                            saved_incomplete_syscall.with_return_value(ret_val, None)
                        }
                        SyscallExitAction::Checkpoint => {
                            syscall_exit_handling_tracer.end();
                            todo!("take a full checkpoint");
                        }
                    };

                    segment.record.push_event(
                        saved_syscall,
                        exit_action == SyscallExitAction::Checkpoint,
                        &segment,
                    )?;
                } else {
                    // outside protected region
                    let segments = self.segments.read();
                    if let Some(last_segment) = segments.last_segment() {
                        drop(segments);

                        if let Some(ongoing_syscall) =
                            last_segment.record.get_last_incomplete_syscall()
                        {
                            assert_eq!(ongoing_syscall.exit_action, SyscallExitAction::Checkpoint);

                            // restore registers as if we haven't modified any flags
                            main.process.modify_registers_with(|regs| {
                                regs.with_syscall_args(ongoing_syscall.syscall.into_parts().1, true)
                            })?;

                            syscall_exit_handling_tracer.end();

                            self.take_main_checkpoint(
                                main,
                                false,
                                false,
                                CheckpointCaller::Shell,
                                None,
                                scope,
                            )?;
                            skip_ptrace_syscall = true;
                        }
                    }
                }
            }
            Inferior::Checker(checker) => {
                let saved_syscall_with_is_last_event = checker
                    .segment
                    .record
                    .pop_syscall()
                    .expect("Unexpected ptrace event");

                if saved_syscall_with_is_last_event.is_last_event {
                    todo!("Take a checkpoint");
                }

                let saved_syscall = saved_syscall_with_is_last_event.value;

                match saved_syscall.exit_action {
                    SyscallExitAction::ReplayEffects => match &saved_syscall.kind {
                        SavedSyscallKind::WithMemoryEffects { mem_written, .. } => {
                            checker.process.modify_registers_with(|regs| {
                                regs.with_syscall_ret_val(saved_syscall.ret_val)
                            })?;
                            mem_written.dump(checker.process.deref_mut())?;
                        }
                        _ => panic!("Cannot replay syscall effects with unknown memory effects"),
                    },
                    SyscallExitAction::ReplicateSyscall => {
                        assert_eq!(ret_val, saved_syscall.ret_val);
                    }
                    SyscallExitAction::Checkpoint => {
                        syscall_exit_handling_tracer.end();
                        todo!("take a full checkpoint");
                    }
                    SyscallExitAction::Custom => {
                        assert_eq!(ret_val, saved_syscall.ret_val);

                        let result = self.dispatcher.handle_standard_syscall_exit_checker(
                            ret_val,
                            &saved_syscall,
                            hctx(&mut checker.into(), self, scope),
                        )?;

                        if result == SyscallHandlerExitAction::NextHandler {
                            panic!("Unhandled custom syscall during syscall exit");
                        }
                    }
                }
            }
        }

        if !skip_ptrace_syscall {
            child.process().resume()?;
        }

        Ok(())
    }

    pub fn handle_custom_syscall_entry<'s, 'scope, 'env>(
        &'s self,
        child: &mut Inferior,
        sysno: usize,
        args: SyscallArgs,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        info!(
            "{child} Syscall: syscall({sysno:#x}, {}, {}, {}, {}, {}, {})",
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5
        );

        let handled = self
            .dispatcher
            .handle_custom_syscall_entry(sysno, args, hctx(&mut child.into(), self, scope))
            .unwrap();

        if handled == SyscallHandlerExitAction::NextHandler
            && (sysno == SYSNO_CHECKPOINT_TAKE || sysno == SYSNO_CHECKPOINT_FINI)
        {
            let is_finishing = sysno == SYSNO_CHECKPOINT_FINI;

            match child {
                Inferior::Main(main) => {
                    if let Some(segment) = &main.segment {
                        segment.record.push_event(
                            ManualCheckpointRequest { is_finishing },
                            true,
                            segment,
                        )?;
                    }

                    self.take_main_checkpoint(
                        main,
                        is_finishing,
                        true,
                        CheckpointCaller::Child,
                        Some(SyscallType::Custom(sysno, args)),
                        scope,
                    )?;
                }
                Inferior::Checker(checker) => {
                    let result = checker.segment.record.pop_manual_checkpoint_request()?;
                    assert!(result.is_last_event);
                    if result.value.is_finishing != is_finishing {
                        return Err(Error::UnexpectedEvent(
                            UnexpectedEventReason::IncorrectTypeOrArguments,
                        ));
                    }
                    self.take_checker_checkpoint(checker)?;
                }
            }
        } else {
            child.process().resume()?;
        }

        Ok(())
    }

    pub fn handle_custom_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        child: &mut Inferior,
        sysno: usize,
        _args: SyscallArgs,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        debug!("{child} Syscall: ... = {ret_val}");
        let handled = self
            .dispatcher
            .handle_custom_syscall_exit(ret_val, hctx(&mut child.into(), self, scope))
            .unwrap();

        if handled == SyscallHandlerExitAction::NextHandler
            && (sysno == SYSNO_CHECKPOINT_TAKE || sysno == SYSNO_CHECKPOINT_FINI)
        {
            child
                .process()
                .modify_registers_with(|r| r.with_syscall_ret_val(0))?;
        }

        child.process().resume()?;

        Ok(())
    }

    pub fn handle_signal<'s, 'scope, 'env>(
        &'s self,
        child: &mut Inferior,
        sig: Signal,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let tracing_event = match child {
            Inferior::Main(_) => timing::Event::MainSignalHandling,
            Inferior::Checker(_) => timing::Event::CheckerSignalHandling,
        };

        let signal_handling_tracer = self.tracer.trace(tracing_event);

        let result = self
            .dispatcher
            .handle_signal(sig, hctx(&mut child.into(), self, scope))?;

        signal_handling_tracer.end();

        match result {
            SignalHandlerExitAction::SkipPtraceSyscall => (),
            SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step } => {
                if single_step {
                    child.process().single_step()?;
                } else {
                    child.process().resume()?;
                }
            }
            SignalHandlerExitAction::NextHandler => {
                info!("{child} Signal: {:}", sig);
                ptrace::syscall(child.process().pid, sig)?;
            }
            SignalHandlerExitAction::ContinueInferior => {
                ptrace::syscall(child.process().pid, sig)?;
            }
            SignalHandlerExitAction::Checkpoint => {
                self.take_checkpoint(child, false, false, CheckpointCaller::Shell, None, scope)?;
            }
        }

        Ok(())
    }

    pub fn push_curr_exec_point_to_event_log(&self, main: &mut Main) -> Result<()> {
        if let Some(segment) = main.segment.as_ref().cloned() {
            let exec_point = self
                .dispatcher
                .get_current_execution_point(&mut main.into())?;

            debug!("{main} New execution point: {exec_point:?}");
            segment.record.push_event(exec_point, true, &segment)?;
        } else {
            return Err(Error::InvalidState);
        }

        Ok(())
    }
}
