use std::collections::HashMap;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};

use std::sync::Arc;
use std::thread::{park, Scope, Thread};

use derive_builder::Builder;
use log::{debug, error, info, warn};

use nix::sys::signal::Signal;
use nix::sys::wait::WaitStatus;

use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};

use reverie_syscalls::{Displayable, Syscall, SyscallArgs, SyscallInfo};
use scopeguard::defer;
use serde::{Deserialize, Serialize};

use crate::dirty_page_trackers::ExtraWritableRangesProvider;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result, UnexpectedEventReason};
use crate::events::hctx;
use crate::events::migration::MigrationHandler;
use crate::events::module_lifetime::ModuleLifetimeHook;
use crate::events::process_lifetime::{pctx, ProcessLifetimeHook};
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
use crate::process::state::{Running, Stopped, Unowned};
use crate::process::Process;
use crate::statistics::timing::{self, Tracer};
use crate::throttlers::Throttler;
use crate::types::chains::SegmentChains;
use crate::types::checker::CheckerStatus;
use crate::types::checkpoint::{Checkpoint, CheckpointCaller};
use crate::types::custom_sysno::CustomSysno;
use crate::types::exit_reason::ExitReason;
use crate::types::process_id::{Checker, Inferior, InferiorRole, Main};
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

pub struct CheckCoordinator<'disp, 'modules, 'tracer: 'disp> {
    pub segments: Arc<RwLock<SegmentChains>>,
    pub main: Process<Unowned>,
    pub epoch: AtomicU32,
    options: CheckCoordinatorOptions,
    pub dispatcher: &'disp Dispatcher<'disp, 'modules>,
    workers: Mutex<HashMap<SegmentId, Worker>>,
    main_thread: Thread,
    aborting: AtomicBool,
    tracer: &'tracer Tracer,
    checker_cpu_set: Vec<usize>,
}

#[derive(Debug, Default, Clone, Builder, Serialize, Deserialize)]
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
pub enum SyscallType {
    Standard(Syscall),
    Custom(usize, SyscallArgs),
}

impl<'disp, 'modules, 'tracer> CheckCoordinator<'disp, 'modules, 'tracer> {
    pub fn new(
        main: Process<Unowned>,
        options: CheckCoordinatorOptions,
        dispatcher: &'disp Dispatcher<'disp, 'modules>,
        tracer: &'tracer Tracer,
        checker_cpu_set: Vec<usize>,
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
            checker_cpu_set,
        }
    }

    fn run_event_loop<'s, 'scope, 'env>(
        &'s self,
        mut child: Inferior<Stopped>,
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
                self.dispatcher.handle_main_init(main, pctx(self, scope))?;
                wall_time_event = timing::Event::MainWall;
            }
            Inferior::Checker(checker) => {
                self.dispatcher
                    .handle_checker_init(checker, pctx(self, scope))?;
                wall_time_event = timing::Event::CheckerWall;
            }
        }

        let wall_time_tracer = self.tracer.trace(wall_time_event);

        let mut child_running = child.try_map_process_noret(|mut x| {
            let sigmask = x.get_sigmask()?;
            x.set_sigmask(sigmask & !(1 << (nix::libc::SIGUSR1 - 1)))?; // SIGUSR1 is used by Process::sigqueue
            x.resume()
        })?;

        // Main loop
        let exit_reason = loop {
            let status;
            (child, status) = child_running
                .try_map_process(|x| Ok::<_, Error>(x.waitpid()?.unwrap_stopped()))
                .expect("waitpid");

            if child.is_main() && self.aborting.load(Ordering::SeqCst) {
                break ExitReason::Cancelled;
            }

            fn get_pre_resume_cb(
                child: &mut Inferior<Stopped>,
            ) -> Result<impl FnOnce(&mut Process<Stopped>) -> Result<()>> {
                let old_sigmask = child.process().get_sigmask()?;
                child.process_mut().set_sigmask(!0)?;

                Ok(move |p: &mut Process<Stopped>| p.set_sigmask(old_sigmask))
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
                    let pre_resume_cb = get_pre_resume_cb(&mut child)?;
                    child_running = self.handle_signal(child, sig, scope, pre_resume_cb)?;
                }
                WaitStatus::PtraceSyscall(_) => {
                    let pre_resume_cb = get_pre_resume_cb(&mut child)?;

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
                                child_running = self.handle_syscall_entry(
                                    child,
                                    syscall,
                                    scope,
                                    pre_resume_cb,
                                )?;
                                ongoing_syscall = Some(SyscallType::Standard(syscall));
                            } else {
                                // Custom syscall entry
                                child_running = self.handle_custom_syscall_entry(
                                    child,
                                    regs.sysno_raw(),
                                    regs.syscall_args(),
                                    scope,
                                    pre_resume_cb,
                                )?;

                                ongoing_syscall = Some(SyscallType::Custom(
                                    regs.sysno_raw(),
                                    regs.syscall_args(),
                                ));
                            }
                        }
                        Some(SyscallType::Standard(syscall)) => {
                            // Standard syscall exit
                            child_running = self.handle_syscall_exit(
                                child,
                                syscall,
                                regs.syscall_ret_val(),
                                scope,
                                pre_resume_cb,
                            )?;

                            ongoing_syscall = None;
                        }
                        Some(SyscallType::Custom(sysno, args)) => {
                            // Custom syscall exit
                            child_running = self.handle_custom_syscall_exit(
                                child,
                                sysno,
                                args,
                                regs.syscall_ret_val(),
                                scope,
                                pre_resume_cb,
                            )?;

                            ongoing_syscall = None;
                        }
                    }
                }
                ws => unreachable!("{ws:?}"),
            }
        };

        wall_time_tracer.end();

        // Dispatch fini and extra checks on segment status
        match &mut child {
            Inferior::Main(main) => {
                self.dispatcher
                    .handle_main_fini(main, &exit_reason, pctx(self, scope))?;
            }
            Inferior::Checker(checker) => {
                self.dispatcher
                    .handle_checker_fini(checker, &exit_reason, pctx(self, scope))?
            }
        }

        info!("{child} Done");

        Ok(exit_reason)
    }

    fn wait_until_unthrottled(
        &self,
        main: &mut Main<Running>,
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
        mut main: Main<Stopped>,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Main<Running>>
    where
        's: 'scope + 'disp,
    {
        let checkpointing_tracer = self.tracer.trace(timing::Event::MainCheckpointing);
        info!("{main} Checkpoint");
        if self.options.no_fork {
            let main = main.try_map_process_noret(|mut p| {
                pre_resume_cb(&mut p)?;
                p.resume()
            })?;

            return Ok(main);
        }

        let mut segments = self.segments.upgradable_read();
        let in_chain = segments.in_chain();

        if !in_chain && is_finishing {
            info!("{main} No-op checkpoint_fini");
            let main = main.try_map_process_noret(|mut p| {
                pre_resume_cb(&mut p)?;
                p.resume()
            })?;
            return Ok(main);
        }

        let epoch_local = self.epoch.fetch_add(1, Ordering::SeqCst);

        let pre_fork_hook_tracer = self
            .tracer
            .trace(timing::Event::MainCheckpointingPreForkHook);
        self.dispatcher
            .handle_checkpoint_created_pre_fork(&mut main, pctx(self, scope))?;
        pre_fork_hook_tracer.end();

        let forking_tracer = self.tracer.trace(timing::Event::MainCheckpointingForking);
        let (mut main, reference) = main.try_map_process(|p| p.fork(restart_old_syscall, true))?;
        forking_tracer.end();

        let post_fork_hook_tracer = self
            .tracer
            .trace(timing::Event::MainCheckpointingPostForkHook);
        self.dispatcher
            .handle_checkpoint_created_post_fork(&mut main, pctx(self, scope))?;
        post_fork_hook_tracer.end();

        let throttler = if in_chain {
            self.dispatcher
                .dispatch_throttle(&mut main, &segments, self)
        } else {
            None
        };

        let mut main = main.try_map_process_noret(|mut p| {
            pre_resume_cb(&mut p)?;
            p.resume()
        })?;
        checkpointing_tracer.end();

        let checkpoint = Checkpoint::new(epoch_local, reference, caller)?;

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
                &mut main,
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

            self.wait_until_unthrottled(&mut main, throttler, &mut segments);
            throttling_tracer.end();
        }

        Ok(main)
    }

    fn take_checker_checkpoint<'s, 'scope, 'env>(
        &'s self,
        mut checker: Checker<Stopped>,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Checker<Running>>
    where
        's: 'scope + 'disp,
    {
        let checker_comparing_tracer = self.tracer.trace(timing::Event::CheckerComparing);

        info!("{checker} Checkpoint");

        self.dispatcher.handle_segment_completed(&mut checker)?;

        let check_fail_reason;

        if self.options.no_state_cmp {
            check_fail_reason = None;
            checker.segment.checker_status.lock().assume_checked();
        } else {
            check_fail_reason = checker.segment.clone().check(
                &mut checker,
                &self.dispatcher.get_ignored_pages(),
                &self.dispatcher.get_extra_writable_ranges(),
                self.dispatcher,
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

        self.dispatcher.handle_segment_checked(
            &mut checker,
            &check_fail_reason,
            pctx(self, scope),
        )?;

        let mut segments = self.segments.write();
        self.cleanup_committed_segments(&mut segments, true)?;
        drop(segments);

        checker_comparing_tracer.end();

        let checker = checker.try_map_process_noret(|mut p| {
            pre_resume_cb(&mut p)?;
            p.kill()
        })?;

        Ok(checker)
    }

    /// Handle checkpoint request from the target
    fn take_checkpoint<'s, 'scope, 'env>(
        &'s self,
        child: Inferior<Stopped>,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        ongoing_syscall: Option<SyscallType>,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Inferior<Running>>
    where
        's: 'scope + 'disp,
    {
        match child {
            Inferior::Main(main) => self
                .take_main_checkpoint(
                    main,
                    is_finishing,
                    restart_old_syscall,
                    caller,
                    ongoing_syscall,
                    scope,
                    pre_resume_cb,
                )
                .map(|x| x.into()),
            Inferior::Checker(checker) => self
                .take_checker_checkpoint(checker, scope, pre_resume_cb)
                .map(|x| x.into()),
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
        process: Process<Stopped>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<ExitReason>
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

            self.dispatcher.fini(pctx(self, scope)).unwrap();
        }
        self.dispatcher.init(pctx(self, scope))?;

        let mut exit_reason = match self.run_event_loop(
            Inferior::Main(Main {
                process: Some(process),
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
            .unwrap_or(Ok(exit_reason))?;

        Ok(exit_reason)
    }

    fn checker_work<'s, 'scope, 'env>(
        &'s self,
        segment: Arc<Segment>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let checker_starting_tracer = self.tracer.trace(timing::Event::CheckerStarting);

        let checker_forking_tracer = self.tracer.trace(timing::Event::CheckerForking);
        let mut checker_process = segment.start_checker(self.checker_cpu_set.clone())?;
        checker_forking_tracer.end();

        if cfg!(debug_assertions) {
            let registers;
            (checker_process, registers) = checker_process.read_registers_precisely()?;
            assert_eq!(registers, segment.reference_start().read_registers()?);
        }

        segment.record.wait_for_initial_event()?;

        if !self.options.no_checker_exec {
            let checker_ready_hook_tracer = self.tracer.trace(timing::Event::CheckerReadyHook);

            let mut checker = Checker {
                process: Some(checker_process),
                segment: segment.clone(),
            };

            self.dispatcher
                .handle_segment_ready(&mut checker, pctx(self, scope))?;
            checker_ready_hook_tracer.end();

            let exit_reason =
                self.run_event_loop(Inferior::Checker(checker), segment.ongoing_syscall, scope)?;

            if exit_reason != ExitReason::NormalExit(0) {
                return Err(Error::UnexpectedCheckerExitReason(exit_reason));
            }
        } else {
            segment.checker_status.lock().assume_checked();
        }
        checker_starting_tracer.end();

        Ok(())
    }

    pub fn start_checker_worker_thread<'s, 'scope, 'env>(
        &'s self,
        segment: Arc<Segment>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        let segment_nr = segment.nr;

        let mut workers = self.workers.lock();

        let jh = std::thread::Builder::new()
            .name(format!("checker-{}", segment.nr))
            .spawn_scoped(scope, move || {
                let ret = catch_unwind(AssertUnwindSafe(|| {
                    self.checker_work(segment.clone(), scope)
                }));

                self.workers.lock().remove(&segment.nr);

                let mut abort = false;

                let checker_id = InferiorRole::Checker(segment.clone());

                match ret {
                    Err(_) => {
                        error!("{checker_id} Panicked");
                        abort = true;
                        *segment.checker_status.lock() = CheckerStatus::Crashed(Error::Panic);
                        self.dispatcher.handle_segment_checker_error(&segment, &Error::Panic, &mut abort, pctx(self, scope)).unwrap();
                    }
                    Ok(Err(e)) => {
                        error!("{checker_id} Failed: {e:?}");
                        abort = true;
                        *segment.checker_status.lock() = CheckerStatus::Crashed(e.clone());
                        self.dispatcher.handle_segment_checker_error(&segment, &e, &mut abort, pctx(self, scope)).unwrap();
                    }
                    Ok(Ok(())) => {
                        let mut checker_status = segment.checker_status.lock();

                        if !checker_status.is_finished() {
                            info!("{checker_id} Checker not marked as finished, assuming it is cancelled");
                            abort = true;
                            *checker_status = CheckerStatus::Crashed(Error::Cancelled);
                            drop(checker_status);
                            self.dispatcher.handle_segment_checker_error(&segment, &Error::Cancelled, &mut abort, pctx(self, scope)).unwrap();
                        }
                    }
                }

                self.cleanup_committed_segments(&mut self.segments.write(), true).unwrap();

                if abort {
                    self.abort_main();
                }

                self.dispatcher.handle_checker_worker_fini(&segment, pctx(self, scope)).unwrap();
            })
            .unwrap();

        workers.insert(
            segment_nr,
            Worker {
                thread: jh.thread().clone(),
            },
        );

        Ok(())
    }

    pub fn abort_main(&self) {
        self.aborting.store(true, Ordering::SeqCst);
        self.main_thread.unpark();
    }

    fn add_checkpoint<'s, 'scope, 'env>(
        &'s self,
        main: &mut Main<Running>,
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
            main.process.as_ref().unwrap().unowned_copy(),
            ongoing_syscall,
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

            self.start_checker_worker_thread(new_segment, scope)?;
        }

        if is_finishing {
            self.dispatcher.handle_segment_chain_closed(main)?;
        }

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

        self.dispatcher.handle_all_fini(pctx(self, scope))?;

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
        mut child: Inferior<Stopped>,
        syscall: Syscall,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Inferior<Running>>
    where
        's: 'scope + 'disp,
    {
        let tracing_event = match child {
            Inferior::Main(_) => timing::Event::MainSyscallEntryHandling,
            Inferior::Checker(_) => timing::Event::CheckerSyscallEntryHandling,
        };

        let syscall_entry_handling_tracer = self.tracer.trace(tracing_event);

        info!("{child} Syscall: {:}", syscall.display(child.process()));

        if matches!(
            self.dispatcher.handle_standard_syscall_entry(
                &syscall,
                hctx(&mut (&mut child).into(), self, scope)
            )?,
            SyscallHandlerExitAction::ContinueInferior
        ) {
            return child.try_map_process_noret(|mut p| {
                pre_resume_cb(&mut p)?;
                p.resume()
            });
        }

        match child {
            Inferior::Main(mut main) => {
                // Main syscall entry
                if let Some(segment) = &main.segment {
                    let segment = segment.clone();
                    // Main syscall entry, inside protection zone

                    let result = self.dispatcher.handle_standard_syscall_entry_main(
                        &syscall,
                        hctx(&mut (&mut main).into(), self, scope),
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

                            main.try_map_process_noret(|mut p| {
                                pre_resume_cb(&mut p)?;
                                p.resume()
                            })
                            .map(|x| x.into())
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
                                pre_resume_cb,
                            )
                            .map(|x| x.into())
                        }
                    }
                } else {
                    main.try_map_process_noret(|mut p| {
                        pre_resume_cb(&mut p)?;
                        p.resume()
                    })
                    .map(|x| x.into())
                }
            }
            Inferior::Checker(mut checker) => {
                // Checker syscall entry
                let result = self.dispatcher.handle_standard_syscall_entry_checker(
                    &syscall,
                    hctx(&mut (&mut checker).into(), self, scope),
                )?;

                match result {
                    StandardSyscallEntryCheckerHandlerExitAction::NextHandler => {
                        panic!("Unhandled syscall exit")
                    }
                    StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior => checker
                        .try_map_process_noret(|mut p| {
                            pre_resume_cb(&mut p)?;
                            p.resume()
                        })
                        .map(|x| x.into()),
                    StandardSyscallEntryCheckerHandlerExitAction::Checkpoint => {
                        let incomplete_syscall = checker.segment.record.pop_incomplete_syscall()?;
                        assert!(incomplete_syscall.is_last_event);
                        syscall_entry_handling_tracer.end();

                        self.take_checker_checkpoint(checker, scope, pre_resume_cb)
                            .map(|p| p.into())
                    }
                }
            }
        }
    }

    pub fn handle_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        mut child: Inferior<Stopped>,
        last_syscall: Syscall,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Inferior<Running>>
    where
        's: 'scope + 'disp,
    {
        debug!("{child} Syscall: ... = {ret_val}");

        let tracing_event = match child {
            Inferior::Main(_) => timing::Event::MainSyscallExitHandling,
            Inferior::Checker(_) => timing::Event::CheckerSyscallExitHandling,
        };

        let syscall_exit_handling_tracer = self.tracer.trace(tracing_event);

        if self.dispatcher.handle_standard_syscall_exit(
            ret_val,
            &last_syscall,
            hctx(&mut (&mut child).into(), self, scope),
        )? == SyscallHandlerExitAction::ContinueInferior
        {
            return child.try_map_process_noret(|mut p| {
                pre_resume_cb(&mut p)?;
                p.resume()
            });
        }

        match child {
            Inferior::Main(mut main) => {
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
                                } => SavedMemory::save(main.process(), mem_written_ranges)?,
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
                                hctx(&mut (&mut main).into(), self, scope),
                            )?;

                            assert!(
                                !matches!(result, SyscallHandlerExitAction::NextHandler),
                                "Unhandled custom syscall during syscall exit"
                            );

                            saved_incomplete_syscall.with_return_value(ret_val, None)
                        }
                        SyscallExitAction::Checkpoint => {
                            syscall_exit_handling_tracer.end();
                            todo!("take a full checkpoint")
                        }
                    };

                    segment.record.push_event(
                        saved_syscall,
                        exit_action == SyscallExitAction::Checkpoint,
                        &segment,
                    )?;

                    main.try_map_process_noret(|mut p| {
                        pre_resume_cb(&mut p)?;
                        p.resume()
                    })
                    .map(|x| x.into())
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
                            main.process_mut().modify_registers_with(|regs| {
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
                                pre_resume_cb,
                            )
                            .map(|x| x.into())
                        } else {
                            main.try_map_process_noret(|mut p| {
                                pre_resume_cb(&mut p)?;
                                p.resume()
                            })
                            .map(|x| x.into())
                        }
                    } else {
                        main.try_map_process_noret(|mut p| {
                            pre_resume_cb(&mut p)?;
                            p.resume()
                        })
                        .map(|x| x.into())
                    }
                }
            }
            Inferior::Checker(mut checker) => {
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
                            checker.process_mut().modify_registers_with(|regs| {
                                regs.with_syscall_ret_val(saved_syscall.ret_val)
                            })?;
                            mem_written.dump(checker.process_mut())?;
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
                            hctx(&mut (&mut checker).into(), self, scope),
                        )?;

                        if result == SyscallHandlerExitAction::NextHandler {
                            panic!("Unhandled custom syscall during syscall exit");
                        }
                    }
                }

                checker
                    .try_map_process_noret(|mut p| {
                        pre_resume_cb(&mut p)?;
                        p.resume()
                    })
                    .map(|x| x.into())
            }
        }
    }

    pub fn handle_custom_syscall_entry<'s, 'scope, 'env>(
        &'s self,
        mut child: Inferior<Stopped>,
        sysno: usize,
        args: SyscallArgs,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Inferior<Running>>
    where
        's: 'scope + 'disp,
    {
        info!(
            "{child} Syscall: syscall({sysno:#x}, {}, {}, {}, {}, {}, {})",
            args.arg0, args.arg1, args.arg2, args.arg3, args.arg4, args.arg5
        );

        let handled = self
            .dispatcher
            .handle_custom_syscall_entry(sysno, args, hctx(&mut (&mut child).into(), self, scope))
            .unwrap();

        if handled == SyscallHandlerExitAction::NextHandler
            && (matches!(
                CustomSysno::from_repr(sysno),
                Some(CustomSysno::CheckpointTake) | Some(CustomSysno::CheckpointFini)
            ))
        {
            let is_finishing = CustomSysno::from_repr(sysno) == Some(CustomSysno::CheckpointFini);

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
                        pre_resume_cb,
                    )
                    .map(|x| x.into())
                }
                Inferior::Checker(checker) => {
                    let result = checker.segment.record.pop_manual_checkpoint_request()?;
                    assert!(result.is_last_event);
                    if result.value.is_finishing != is_finishing {
                        error!("{checker} Unexpected checkpoint request");
                        return Err(Error::UnexpectedEvent(
                            UnexpectedEventReason::IncorrectValue,
                        ));
                    }
                    self.take_checker_checkpoint(checker, scope, pre_resume_cb)
                        .map(|x| x.into())
                }
            }
        } else {
            child.try_map_process_noret(|mut p| {
                pre_resume_cb(&mut p)?;
                p.resume()
            })
        }
    }

    pub fn handle_custom_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        mut child: Inferior<Stopped>,
        sysno: usize,
        _args: SyscallArgs,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Inferior<Running>>
    where
        's: 'scope + 'disp,
    {
        debug!("{child} Syscall: ... = {ret_val}");
        let handled = self
            .dispatcher
            .handle_custom_syscall_exit(ret_val, hctx(&mut (&mut child).into(), self, scope))
            .unwrap();

        if handled == SyscallHandlerExitAction::NextHandler
            && (matches!(
                CustomSysno::from_repr(sysno),
                Some(CustomSysno::CheckpointTake) | Some(CustomSysno::CheckpointFini)
            ))
        {
            child
                .process_mut()
                .modify_registers_with(|r| r.with_syscall_ret_val(0))?;
        }

        child.try_map_process_noret(|mut p| {
            pre_resume_cb(&mut p)?;
            p.resume()
        })
    }

    pub fn handle_signal<'s, 'scope, 'env>(
        &'s self,
        mut child: Inferior<Stopped>,
        sig: Signal,
        scope: &'scope Scope<'scope, 'env>,
        pre_resume_cb: impl FnOnce(&mut Process<Stopped>) -> Result<()>,
    ) -> Result<Inferior<Running>>
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
            .handle_signal(sig, hctx(&mut (&mut child).into(), self, scope))?;

        signal_handling_tracer.end();

        match result {
            SignalHandlerExitAction::SkipPtraceSyscall => todo!(),
            SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step } => {
                if single_step {
                    Ok(child.try_map_process_noret(|mut p| {
                        pre_resume_cb(&mut p)?;
                        p.single_step()
                    })?)
                } else {
                    Ok(child.try_map_process_noret(|mut p| {
                        pre_resume_cb(&mut p)?;
                        p.resume()
                    })?)
                }
            }
            SignalHandlerExitAction::NextHandler => {
                info!("{child} Signal: {:}", sig);
                Ok(child.try_map_process_noret(|mut p| {
                    pre_resume_cb(&mut p)?;
                    p.resume_with_signal(sig)
                })?)
            }
            SignalHandlerExitAction::ContinueInferior => {
                Ok(child.try_map_process_noret(|mut p| {
                    pre_resume_cb(&mut p)?;
                    p.resume_with_signal(sig)
                })?)
            }
            SignalHandlerExitAction::Checkpoint => Ok(self.take_checkpoint(
                child,
                false,
                false,
                CheckpointCaller::Shell,
                None,
                scope,
                pre_resume_cb,
            )?),
        }
    }

    pub fn push_curr_exec_point_to_event_log(
        &self,
        main: &mut Main<Stopped>,
        is_finishing: bool,
    ) -> Result<()> {
        if let Some(segment) = main.segment.as_ref().cloned() {
            let exec_point = self
                .dispatcher
                .get_current_execution_point(&mut main.into())?;

            debug!("{main} New execution point: {exec_point:?}");
            segment
                .record
                .push_event(exec_point, is_finishing, &segment)?;
        } else {
            return Err(Error::InvalidState);
        }

        Ok(())
    }

    pub fn migrate_checker<'s, 'scope, 'env>(
        &'s self,
        new_cpu_set: Vec<usize>,
        checker: &mut Checker<Stopped>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
    {
        checker
            .segment
            .checker_status
            .lock()
            .set_cpu_set(new_cpu_set)?;

        self.dispatcher
            .handle_checker_migration(hctx(&mut checker.into(), self, scope))?;

        Ok(())
    }
}
