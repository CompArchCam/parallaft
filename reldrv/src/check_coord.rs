use std::borrow::Borrow;
use std::collections::HashMap;
use std::fmt::Display;
use std::ops::Deref;
use std::sync::atomic::{AtomicU32, Ordering};

use std::sync::Arc;
use std::thread::{park, Scope, Thread};

use derive_builder::Builder;
use log::{debug, error, info, warn};

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitStatus};

use parking_lot::lock_api::{ArcRwLockReadGuard, ArcRwLockUpgradableReadGuard};
use parking_lot::{Mutex, RwLock, RwLockUpgradableReadGuard};

use reverie_syscalls::{Displayable, Syscall, SyscallArgs, SyscallInfo};
use scopeguard::defer;

use crate::dirty_page_trackers::ExtraWritableRangesProvider;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, Result};
use crate::events::process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::events::syscall::{
    CustomSyscallHandler, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler, SyscallHandlerExitAction,
};
use crate::events::{
    segment::SegmentEventHandler,
    signal::{SignalHandler, SignalHandlerExitAction},
    HandlerContext,
};
use crate::process::dirty_pages::IgnoredPagesProvider;
use crate::process::Process;
use crate::syscall_handlers::{SYSNO_CHECKPOINT_FINI, SYSNO_CHECKPOINT_TAKE};
use crate::throttlers::Throttler;
use crate::types::chains::SegmentChains;
use crate::types::checker::CheckerStatus;
use crate::types::checkpoint::{Checkpoint, CheckpointCaller};
use crate::types::segment::{Segment, SegmentId, SegmentStatus};
use crate::types::segment_record::saved_memory::SavedMemory;
use crate::types::segment_record::saved_syscall::{
    SavedIncompleteSyscallKind, SavedSyscallKind, SyscallExitAction,
};

#[macro_export]
macro_rules! ctx {
    ($child:expr, $scope:expr, $coord:expr) => {
        HandlerContext {
            child: $child,
            scope: $scope,
            check_coord: $coord,
        }
    };
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessRole {
    Main,
    Checker,
}

pub type UpgradableReadGuard<T> = ArcRwLockUpgradableReadGuard<parking_lot::RawRwLock, T>;
pub type ReadGuard<T> = ArcRwLockReadGuard<parking_lot::RawRwLock, T>;

#[derive(Debug, Clone)]
pub enum ProcessIdentity<P: Borrow<Process>> {
    Main(P),
    Checker(Arc<RwLock<Segment>>),
}

impl<P: Borrow<Process>> ProcessIdentity<P> {
    pub fn upgradable_read_arc<'s>(
        &'s self,
    ) -> ProcessIdentityRef<'s, UpgradableReadGuard<Segment>> {
        match self {
            ProcessIdentity::Main(p) => ProcessIdentityRef::Main(p.borrow()),
            ProcessIdentity::Checker(segment) => {
                ProcessIdentityRef::Checker(segment.upgradable_read_arc())
            }
        }
    }

    pub fn read_arc_recursive<'s>(&'s self) -> ProcessIdentityRef<'s, ReadGuard<Segment>> {
        match self {
            ProcessIdentity::Main(p) => ProcessIdentityRef::Main(p.borrow()),
            ProcessIdentity::Checker(segment) => {
                ProcessIdentityRef::Checker(segment.read_arc_recursive())
            }
        }
    }

    pub fn is_main(&self) -> bool {
        matches!(self, ProcessIdentity::Main { .. })
    }

    pub fn is_checker(&self) -> bool {
        matches!(self, ProcessIdentity::Checker { .. })
    }
}

#[derive(Debug)]
pub enum ProcessIdentityRef<'p, T: Deref<Target = Segment>> {
    Main(&'p Process),
    Checker(T),
}

impl<T: Deref<Target = Segment>> ProcessIdentityRef<'_, T> {
    pub fn process(&self) -> Option<&Process> {
        match self {
            ProcessIdentityRef::Main(main) => Some(main),
            ProcessIdentityRef::Checker(segment) => segment.checker.process().map(|x| x.deref()),
        }
    }

    pub fn is_main(&self) -> bool {
        matches!(self, ProcessIdentityRef::Main(_))
    }

    pub fn is_checker(&self) -> bool {
        matches!(self, ProcessIdentityRef::Checker(_))
    }

    pub fn unwrap_checker_segment(&self) -> &T {
        match self {
            ProcessIdentityRef::Main(_) => panic!(
                "called `ProcessIdentityRef::unwrap_checker_segment()` on a `Main(..)` value"
            ),
            ProcessIdentityRef::Checker(s) => s,
        }
    }

    pub fn unwrap_checker_segment_mut(&mut self) -> &mut T {
        match self {
            ProcessIdentityRef::Main(_) => panic!(
                "called `ProcessIdentityRef::unwrap_checker_segment_mut()` on a `Main(..)` value"
            ),
            ProcessIdentityRef::Checker(s) => s,
        }
    }
}

impl<T: Deref<Target = Segment>> Display for ProcessIdentityRef<'_, T> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            ProcessIdentityRef::Main(_) => write!(f, "[M      ]"),
            ProcessIdentityRef::Checker(s) => write!(f, "[C{:>6}]", s.nr),
        }
    }
}

#[derive(Debug)]
struct Worker {
    thread: Thread,
}

pub struct CheckCoordinator<'disp, 'modules> {
    pub segments: Arc<RwLock<SegmentChains>>,
    pub main: Process,
    pub epoch: AtomicU32,
    options: CheckCoordinatorOptions,
    pub dispatcher: &'disp Dispatcher<'disp, 'modules>,
    workers: Mutex<HashMap<SegmentId, Worker>>,
    main_thread: Thread,
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
}

pub type ExitCode = i32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExitReason {
    NormalExit(ExitCode),
    Signalled(Signal),
    UnexpectedlyDies,
    StateMismatch,
    Panic,
}

impl ExitReason {
    pub fn exit_code(&self) -> ExitCode {
        match self {
            ExitReason::NormalExit(c) => *c,
            ExitReason::Signalled(sig) => 128 + (*sig as i32),
            ExitReason::StateMismatch => 253,
            ExitReason::UnexpectedlyDies => 254,
            ExitReason::Panic => 255,
        }
    }

    pub fn expect(self) {
        self.expect_exit_code(0);
    }

    pub fn expect_panic(self) {
        assert_eq!(self, ExitReason::Panic);
    }

    pub fn expect_exit_code(self, code: ExitCode) {
        assert_eq!(self, ExitReason::NormalExit(code));
    }

    pub fn expect_state_mismatch(self) {
        assert_eq!(self, ExitReason::StateMismatch);
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum SyscallType {
    Standard(Syscall),
    Custom,
}

impl<'disp, 'modules> CheckCoordinator<'disp, 'modules>
where
    'modules: 'disp,
{
    pub fn new(
        main: Process,
        options: CheckCoordinatorOptions,
        dispatcher: &'disp Dispatcher<'disp, 'modules>,
    ) -> Self {
        Self {
            segments: Arc::new(RwLock::new(SegmentChains::new())),
            main,
            epoch: AtomicU32::new(0),
            options,
            dispatcher,
            workers: Mutex::new(HashMap::new()),
            main_thread: std::thread::current(),
        }
    }

    pub fn run_event_loop<'s, 'scope, 'env, P>(
        &'s self,
        child: ProcessIdentity<P>,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<ExitReason>
    where
        's: 'scope,
        's: 'disp,
        P: Borrow<Process>,
    {
        let child_ref = child.read_arc_recursive();
        info!("{child_ref} Ready");
        let process = child_ref.process().unwrap().clone(); /* TODO */
        drop(child_ref);

        let process_ctx = ProcessLifetimeHookContext {
            process: &process,
            check_coord: self,
            scope,
        };

        let mut last_syscall_type = None;

        // Dispatch init
        match child {
            ProcessIdentity::Main(_) => {
                self.dispatcher.handle_main_init(process_ctx).unwrap();
            }
            ProcessIdentity::Checker(_) => {
                self.dispatcher.handle_checker_init(process_ctx).unwrap();
            }
        }

        process.resume()?;

        // Main loop
        let exit_reason = loop {
            let status;

            match waitpid(process.pid, None) {
                Ok(s) => status = s,
                Err(Errno::ECHILD) => break ExitReason::UnexpectedlyDies,
                Err(e) => panic!("waitpid error {e:?}"),
            }

            let mut child_ref = child.upgradable_read_arc();

            if child_ref.is_main() {
                // todo select! with waitpid
                if self.has_errors() {
                    break ExitReason::StateMismatch;
                }
            }

            match status {
                WaitStatus::Exited(_, status) => {
                    if child_ref.is_main() {
                        info!("{child_ref} Exit: {status}");
                    }
                    break ExitReason::NormalExit(status);
                }
                WaitStatus::Signaled(_, sig, _) => {
                    if child_ref.is_checker() && sig == Signal::SIGKILL {
                        break ExitReason::NormalExit(0);
                    }

                    info!("{child_ref} Signal: {sig}");
                    break ExitReason::Signalled(sig);
                }
                WaitStatus::Stopped(_, sig) => {
                    self.handle_signal(&mut child_ref, sig, scope).unwrap();
                }
                WaitStatus::PtraceSyscall(_) => {
                    // Tell if it is a syscall entry or exit
                    let is_syscall_entry = process.syscall_dir().unwrap().is_entry();
                    assert_eq!(is_syscall_entry, last_syscall_type.is_none());

                    let regs = process_ctx.process.read_registers().unwrap();

                    match last_syscall_type {
                        None => {
                            // Syscall entry
                            if let Some(sysno) = regs.sysno() {
                                let syscall = Syscall::from_raw(sysno, regs.syscall_args());
                                // Standard syscall entry
                                self.handle_syscall_entry(&mut child_ref, syscall, scope)
                                    .unwrap();

                                drop(child_ref);

                                last_syscall_type = Some(SyscallType::Standard(syscall));
                            } else {
                                // Custom syscall entry
                                self.handle_custom_syscall_entry(
                                    &mut child_ref,
                                    regs.sysno_raw(),
                                    regs.syscall_args(),
                                    scope,
                                )
                                .unwrap();

                                last_syscall_type = Some(SyscallType::Custom);
                            }
                        }
                        Some(SyscallType::Standard(syscall)) => {
                            // Standard syscall exit
                            self.handle_syscall_exit(
                                &mut child_ref,
                                syscall,
                                regs.syscall_ret_val(),
                                scope,
                            )
                            .unwrap();

                            last_syscall_type = None;
                        }
                        Some(SyscallType::Custom) => {
                            // Custom syscall exit
                            self.handle_custom_syscall_exit(
                                &mut child_ref,
                                regs.syscall_ret_val(),
                                scope,
                            )
                            .unwrap();

                            last_syscall_type = None;
                        }
                    }
                }
                WaitStatus::StillAlive => continue,
                ws @ _ => unreachable!("{ws:?}"),
            }
        };

        // Dispatch fini and extra checks on segment status
        match &child {
            ProcessIdentity::Main(_) => {
                self.dispatcher
                    .handle_main_fini(
                        match exit_reason {
                            ExitReason::NormalExit(ret) => ret,
                            _ => -1,
                        }, /* todo */
                        process_ctx,
                    )
                    .unwrap();
            }
            ProcessIdentity::Checker(segment) => {
                assert!(segment.read().is_checked());

                self.dispatcher
                    .handle_checker_fini(None /* todo */, process_ctx)
                    .unwrap()
            }
        }

        let child_ref = child.read_arc_recursive();
        info!("{child_ref} Done");
        drop(child_ref);

        Ok(exit_reason)
    }

    fn wait_until_unthrottled(
        &self,
        throttler: &(dyn Throttler + Sync),
        segments: &mut RwLockUpgradableReadGuard<SegmentChains>, // TODO: changeme
    ) {
        loop {
            RwLockUpgradableReadGuard::unlocked(segments, || {
                park();
            });

            if !self.options.ignore_miscmp && segments.has_errors() {
                break;
            }

            if throttler.should_unthrottle(&segments, self) {
                info!("Unthrottled");
                break;
            }
            if segments.nr_live_segments() == 0 {
                panic!(
                    "Deadlock detected: unthrottle not called after the number of live segments reaching zero"
                );
            }
        }
    }

    fn handle_main_checkpoint<'s, 'scope, 'env>(
        &'s self,
        process: &Process,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        info!("[M      ] Checkpoint");
        if self.options.no_fork {
            process.resume()?;
            return Ok(());
        }

        let mut segments = self.segments.upgradable_read();
        let in_chain = segments.in_chain();

        if !in_chain && is_finishing {
            info!("No-op checkpoint_fini");
            process.resume()?;
            return Ok(());
        }

        let epoch_local = self.epoch.fetch_add(1, Ordering::SeqCst);

        let reference = process.fork(restart_old_syscall, true)?;

        self.dispatcher.handle_checkpoint_created_pre(
            process.pid,
            if segments.next_id == 0 {
                None
            } else {
                Some(segments.next_id - 1)
            },
        )?;

        let throttler;

        if in_chain {
            throttler = self.dispatcher.dispatch_throttle(&segments, self);
        } else {
            throttler = None;
        }

        process.resume()?;

        let checkpoint = Checkpoint::new(epoch_local, reference, caller);

        match (in_chain, is_finishing) {
            (false, false) => {
                // Start of the segment chain
                info!("[M      ] Protection on");
            }
            (true, false) => {
                // Middle of the segment chain
            }
            (true, true) => {
                // End of the segment chain
                info!("[M      ] Protection off");
            }
            _ => unreachable!(),
        }

        debug!("New checkpoint: {:#?}", checkpoint);
        segments.with_upgraded(|segments_mut| {
            self.add_checkpoint(segments_mut, checkpoint, is_finishing, scope)
        })?;

        if let Some(throttler) = throttler {
            self.wait_until_unthrottled(throttler, &mut segments);
        }

        Ok(())
    }

    pub fn handle_checker_checkpoint<'s, 'scope, 'env>(
        &'s self,
        segment: &mut UpgradableReadGuard<Segment>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        segment.with_upgraded(|segment| {
            info!("[C{:>6}] Checkpoint", segment.nr);

            if self.options.no_state_cmp {
                segment.mark_as_checked(false);
            } else {
                match segment.check(
                    self.main.pid,
                    &self.dispatcher.get_ignored_pages(),
                    &self.dispatcher.get_extra_writable_ranges(),
                    self.dispatcher,
                    self.dispatcher,
                ) {
                    Ok((result, _nr_dirty_pages)) => {
                        self.dispatcher.handle_segment_checked(&segment).unwrap();

                        if result.is_err() {
                            if self.options.ignore_miscmp {
                                warn!("Check fails");
                            } else {
                                error!("Check fails");
                            }

                            // self.main.dump_memory_maps();
                        } else {
                            info!("Check passed");
                        }

                        segment.mark_as_checked(result.is_err());
                    }
                    Err(e) => {
                        error!("Failed to check: {:?}", e);
                        segment.mark_as_checked(true);
                    }
                }
            }
        });

        UpgradableReadGuard::unlocked(segment, || {
            let mut segments = self.segments.write();
            self.cleanup_committed_segments(&mut segments, true)
        })?;

        Ok(())
    }

    /// Handle checkpoint request from the target
    pub fn handle_checkpoint<'s, 'scope, 'env>(
        &'s self,
        child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        match child {
            ProcessIdentityRef::Main(process) => self.handle_main_checkpoint(
                process,
                is_finishing,
                restart_old_syscall,
                caller,
                scope,
            ),
            ProcessIdentityRef::Checker(segment) => self.handle_checker_checkpoint(segment),
        }
    }

    fn cleanup_committed_segments(
        &self,
        segments: &mut SegmentChains,
        keep_failed_segments: bool,
    ) -> Result<()> {
        segments.cleanup_committed_segments(keep_failed_segments, |segment| {
            self.dispatcher.handle_segment_removed(segment)
        })?;

        self.main_thread.unpark();

        Ok(())
    }

    /// Create a new checkpoint and kick off the checker of the previous checkpoint if needed.
    fn add_checkpoint<'s, 'scope, 'env>(
        &'s self,
        segments: &mut SegmentChains,
        checkpoint: Checkpoint,
        is_finishing: bool,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        segments.add_checkpoint(
            checkpoint,
            is_finishing,
            |mut last_segment, _| {
                let ret = if self.options.no_checker_exec {
                    last_segment.mark_as_checked(false);

                    Ok(true)
                } else {
                    Ok(false)
                };

                self.workers
                    .lock()
                    .get(&last_segment.nr)
                    .unwrap()
                    .thread
                    .unpark();

                ret
            },
            |segment| {
                self.dispatcher.handle_segment_created(&segment)?;

                let segment_id = segment.nr;
                let segment = ArcRwLockReadGuard::rwlock(&segment).clone();

                let mut workers = self.workers.lock();

                let jh = std::thread::Builder::new()
                    .name(format!("checker-{segment_id}"))
                    .spawn_scoped(scope, move || {
                        let segment_temp = segment.clone();
                        defer! {
                            let mut s = segment_temp.write();
                            if !matches!(s.checker.status, CheckerStatus::Checked(..)) {
                                warn!("Checker worker possibly crashed without marking segment as checked");
                                s.checker.status = CheckerStatus::Crashed(Error::Panic)
                            }
                            self.workers.lock().remove(&segment_id).unwrap();
                        }

                        loop {
                            let segment_locked = segment.read();
                            match &segment_locked.status {
                                SegmentStatus::Filling => (),
                                SegmentStatus::Done(..) => {
                                    break;
                                }
                                SegmentStatus::Crashed => {
                                    warn!("Main process fails to complete segment");
                                    return;
                                }
                            }

                            drop(segment_locked);

                            park();
                        }

                        let mut segment_locked = segment.write();
                        segment_locked.start_checker().unwrap();
                        self.dispatcher.handle_segment_ready(&mut segment_locked).unwrap();
                        drop(segment_locked);

                        self.run_event_loop(
                            ProcessIdentity::Checker::<Process>(segment),
                            scope,
                        )
                        .unwrap();
                    })
                    .unwrap();

                workers.insert(
                    segment_id,
                    Worker {
                        thread: jh.thread().clone(),
                    },
                );

                Ok(())
            },
            |segment| self.dispatcher.handle_segment_chain_closed(&segment),
            |segments| self.cleanup_committed_segments(segments, true),
        )
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Check if all checkers has finished.
    pub fn is_all_finished(&self) -> bool {
        self.segments.read().is_empty()
    }

    /// Wait until all segments are checked, and call `disp.handle_all_fini()``. Needs to be called from the main thread
    pub fn wait_until_and_handle_completion<'s, 'scope>(
        &'s self,
        scope: &'scope Scope<'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        while !self.is_all_finished() && !self.has_errors() {
            park();
        }
        self.dispatcher.handle_all_fini(ProcessLifetimeHookContext {
            process: &self.main,
            check_coord: self,
            scope,
        })
    }

    pub fn handle_panic(&self) {
        // Mark all incomplete segments as crashed
        let segments = self.segments.write();
        for segment in &segments.list {
            let mut segment = segment.write();

            match &segment.status {
                SegmentStatus::Filling => {
                    segment.status = SegmentStatus::Crashed;
                }
                SegmentStatus::Done(_) => {
                    if matches!(
                        segment.checker.status,
                        CheckerStatus::Checking(..) | CheckerStatus::NotReady
                    ) {
                        segment.checker.status = CheckerStatus::Crashed(Error::Panic);
                    }
                }
                _ => (),
            }
        }

        drop(segments);

        // Wake up all workers
        let workers = self.workers.lock();

        for worker in workers.values() {
            worker.thread.unpark();
        }
    }

    /// Check if any checker has errors unless IGNORE_CHECK_ERRORS is set.
    pub fn has_errors(&self) -> bool {
        !self.options.ignore_miscmp && self.segments.read().has_errors()
    }

    pub fn handle_syscall_entry<'s, 'scope, 'env>(
        &'s self,
        child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
        syscall: Syscall,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let process = child.process().unwrap().clone(); // hack

        let mut skip_ptrace_syscall = false;

        info!("{child} Syscall: {:}", syscall.display(&process));

        if matches!(
            self.dispatcher
                .handle_standard_syscall_entry(&syscall, ctx!(child, scope, self))?,
            SyscallHandlerExitAction::ContinueInferior
        ) {
            process.resume()?;
            return Ok(());
        }

        match child {
            ProcessIdentityRef::Main(_) => {
                // Main syscall entry
                let segments = self.segments.read();
                if let Some(segment) = segments.main_segment() {
                    // Main syscall entry, inside protection zone
                    let mut segment = segment.write_arc();
                    drop(segments);

                    assert!(
                        segment.record.ongoing_syscall.is_none(),
                        "Syscall double entry"
                    );

                    let result = self
                        .dispatcher
                        .handle_standard_syscall_entry_main(&syscall, ctx!(child, scope, self))?;

                    match result {
                        StandardSyscallEntryMainHandlerExitAction::NextHandler => {
                            panic!("Unhandled syscall entry")
                        }
                        StandardSyscallEntryMainHandlerExitAction::StoreSyscall(
                            saved_incomplete_syscall,
                        ) => {
                            segment.record.ongoing_syscall = Some(saved_incomplete_syscall);
                        }
                        StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                            saved_incomplete_syscall,
                        ) => {
                            segment.record.ongoing_syscall = Some(saved_incomplete_syscall);
                            drop(segment);

                            self.handle_checkpoint(
                                child,
                                true,
                                true,
                                CheckpointCaller::Shell,
                                scope,
                            )?;

                            skip_ptrace_syscall = true;
                        }
                    }
                }
            }
            ProcessIdentityRef::Checker(_) => {
                // Checker syscall entry
                let result = self
                    .dispatcher
                    .handle_standard_syscall_entry_checker(&syscall, ctx!(child, scope, self))?;

                match result {
                    StandardSyscallEntryCheckerHandlerExitAction::NextHandler => {
                        panic!("Unhandled syscall exit")
                    }
                    StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior => (),
                    StandardSyscallEntryCheckerHandlerExitAction::Checkpoint => {
                        self.handle_checker_checkpoint(child.unwrap_checker_segment_mut())?;

                        skip_ptrace_syscall = true;
                    }
                }
            }
        }

        if !skip_ptrace_syscall {
            process.resume()?;
        }

        Ok(())
    }

    pub fn handle_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
        last_syscall: Syscall,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let process = child.process().unwrap().clone();
        let mut skip_ptrace_syscall = false;

        if self.dispatcher.handle_standard_syscall_exit(
            ret_val,
            &last_syscall,
            ctx!(child, scope, self),
        )? == SyscallHandlerExitAction::ContinueInferior
        {
            process.resume()?;
            return Ok(());
        }

        match child {
            ProcessIdentityRef::Main(_) => {
                let segments = self.segments.read();
                if let Some(segment) = segments.main_segment() {
                    // Main syscall entry, inside protection zone
                    drop(segments);
                    let mut segment = segment.write();

                    let saved_incomplete_syscall = segment
                        .record
                        .ongoing_syscall
                        .take()
                        .expect("Unexpected ptrace event");

                    let saved_syscall = match saved_incomplete_syscall.exit_action {
                        SyscallExitAction::ReplicateMemoryWrites => {
                            // TODO: move this to syscall_handlers/record_replay.rs

                            // store memory contents that are potentially written during the syscall
                            let mem_written = match &saved_incomplete_syscall.kind {
                                SavedIncompleteSyscallKind::KnownMemoryRAndWRange {
                                    mem_written_ranges,
                                    ..
                                } => SavedMemory::save(&process, &mem_written_ranges)?,
                                _ => panic!(),
                            };

                            saved_incomplete_syscall.upgrade(ret_val, Some(mem_written))
                        }
                        SyscallExitAction::ReplicateSyscall => {
                            saved_incomplete_syscall.upgrade(ret_val, None)
                        }
                        SyscallExitAction::Custom => {
                            let result = self.dispatcher.handle_standard_syscall_exit_main(
                                ret_val,
                                &saved_incomplete_syscall,
                                ctx!(child, scope, self),
                            )?;

                            if matches!(result, SyscallHandlerExitAction::NextHandler) {
                                panic!("Unhandled custom syscall during syscall exit");
                            };

                            saved_incomplete_syscall.upgrade(ret_val, None)
                        }
                        SyscallExitAction::Checkpoint => {
                            todo!("take a full checkpoint");
                        }
                    };

                    segment.record.push_syscall(saved_syscall);
                } else {
                    // outside protected region
                    if let Some(last_segment) = segments.last_segment() {
                        let mut last_segment = last_segment.write_arc();
                        drop(segments);

                        if let Some(ongoing_syscall) = last_segment.record.ongoing_syscall.take() {
                            assert!(child.is_main());
                            assert_eq!(ongoing_syscall.exit_action, SyscallExitAction::Checkpoint);
                            drop(last_segment);

                            // restore registers as if we haven't modified any flags
                            process.modify_registers_with(|regs| {
                                regs.with_syscall_args(ongoing_syscall.syscall.into_parts().1)
                            })?;

                            self.handle_checkpoint(
                                child,
                                false,
                                false,
                                CheckpointCaller::Shell,
                                scope,
                            )?;
                            skip_ptrace_syscall = true;
                        }
                    }
                }
            }
            ProcessIdentityRef::Checker(segment) => {
                let saved_syscall = segment.with_upgraded(|segment| {
                    segment
                        .record
                        .next_syscall()
                        .expect("Unexpected ptrace event")
                });

                match saved_syscall.exit_action {
                    SyscallExitAction::ReplicateMemoryWrites => {
                        match &saved_syscall.kind {
                            SavedSyscallKind::KnownMemoryRw { mem_written, .. } => {
                                segment.checker.process().unwrap().modify_registers_with(
                                    |regs| regs.with_syscall_ret_val(saved_syscall.ret_val),
                                )?;
                                mem_written.dump(&mut process.clone())?;
                            }
                            _ => panic!(
                                "Cannot replicate syscall effects with unknown memory effect"
                            ),
                        }
                    }
                    SyscallExitAction::ReplicateSyscall => {
                        assert_eq!(ret_val, saved_syscall.ret_val);
                    }
                    SyscallExitAction::Checkpoint => todo!("take a full checkpoint"),
                    SyscallExitAction::Custom => {
                        // dbg!(&saved_syscall);
                        assert_eq!(ret_val, saved_syscall.ret_val);

                        let result = self.dispatcher.handle_standard_syscall_exit_checker(
                            ret_val,
                            &saved_syscall,
                            ctx!(child, scope, self),
                        )?;

                        if result == SyscallHandlerExitAction::NextHandler {
                            panic!("Unhandled custom syscall during syscall exit");
                        }
                    }
                }
            }
        }

        if !skip_ptrace_syscall {
            process.resume()?;
        }

        Ok(())
    }

    pub fn handle_custom_syscall_entry<'s, 'scope, 'env>(
        &'s self,
        child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
        sysno: usize,
        args: SyscallArgs,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let process = child.process().unwrap().clone(); /* hack */

        let handled = self
            .dispatcher
            .handle_custom_syscall_entry(sysno, args, ctx!(child, scope, self))
            .unwrap();

        if handled == SyscallHandlerExitAction::NextHandler {
            match sysno {
                SYSNO_CHECKPOINT_TAKE => {
                    self.handle_checkpoint(
                        child,
                        false,
                        true, /* todo */
                        CheckpointCaller::Child,
                        scope,
                    )?;
                }
                SYSNO_CHECKPOINT_FINI => {
                    self.handle_checkpoint(
                        child,
                        true,
                        true, /* todo */
                        CheckpointCaller::Child,
                        scope,
                    )?;
                }
                _ => process.resume()?,
            }
        } else {
            process.resume()?;
        }

        Ok(())
    }

    pub fn handle_custom_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        self.dispatcher
            .handle_custom_syscall_exit(ret_val, ctx!(child, scope, self))
            .unwrap();

        child.process().unwrap().resume()?;

        Ok(())
    }

    pub fn handle_signal<'s, 'scope, 'env>(
        &'s self,
        child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
        sig: Signal,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let result = self
            .dispatcher
            .handle_signal(sig, ctx!(child, scope, self))?;

        let process = child.process().unwrap();
        let pid = process.pid;

        match result {
            SignalHandlerExitAction::SkipPtraceSyscall => (),
            SignalHandlerExitAction::SuppressSignalAndContinueInferior => {
                process.resume()?;
            }
            SignalHandlerExitAction::NextHandler => {
                info!("{child} Signal: {:}", sig);
                ptrace::syscall(pid, sig)?;
            }
            SignalHandlerExitAction::ContinueInferior => {
                ptrace::syscall(pid, sig)?;
            }
            SignalHandlerExitAction::Checkpoint => {
                self.handle_checkpoint(child, false, false, CheckpointCaller::Shell, scope)?;
            }
        }

        Ok(())
    }
}
