use std::collections::HashMap;

use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::thread::Scope;

use bitflags::bitflags;

use log::{error, info, warn};
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::RemoteIoVec;

use nix::{sched::CloneFlags, unistd::Pid};

use parking_lot::{Mutex, RwLock};

use reverie_syscalls::{Displayable, Syscall, SyscallArgs, SyscallInfo, Sysno};

use crate::dirty_page_trackers::ExtraWritableRangesProvider;
use crate::dispatcher::Dispatcher;
use crate::error::{Error, EventFlags, Result};
use crate::process::dirty_pages::IgnoredPagesProvider;
use crate::process::{OwnedProcess, Process, ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::saved_syscall::{
    SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedMemory, SavedSyscallKind,
    SyscallExitAction,
};
use crate::segments::{Checkpoint, CheckpointCaller, SegmentChain, SegmentEventHandler};
use crate::signal_handlers::{SignalHandler, SignalHandlerExitAction};
use crate::syscall_handlers::{
    HandlerContext, StandardSyscallEntryCheckerHandlerExitAction,
    StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler, SyscallHandlerExitAction,
};
use crate::throttlers::Throttler;
use reverie_syscalls::may_rw::{SyscallMayRead, SyscallMayWrite};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum ProcessRole {
    Main,
    Checker,
}

pub struct CheckCoordinator<'disp> {
    pub segments: Arc<RwLock<SegmentChain>>,
    pub main: Arc<OwnedProcess>,
    pub epoch: AtomicU32,
    throttling: Mutex<Option<&'disp (dyn Throttler + Sync)>>,
    pending_sync: Arc<Mutex<Option<u32>>>,
    flags: CheckCoordinatorFlags,
    pub dispatcher: &'disp Dispatcher<'disp>,
    last_syscall: Mutex<HashMap<Pid, Syscall>>,
}

bitflags! {
    #[derive(Default)]
    pub struct CheckCoordinatorFlags: u32 {
        const NO_MEM_CHECK = 0b00000010;
        const DONT_RUN_CHECKER = 0b00000100;
        const DONT_FORK = 0b00100000;
        const IGNORE_CHECK_ERRORS = 0b01000000;
        const NO_NR_DIRTY_PAGES_LOGGING = 0b10000000;
    }
}

#[allow(unused)]
impl<'disp> CheckCoordinator<'disp> {
    pub fn new(
        main: OwnedProcess,
        flags: CheckCoordinatorFlags,
        dispatcher: &'disp Dispatcher,
    ) -> Self {
        // main.pid
        let main_pid = main.pid;
        Self {
            main: Arc::new(main),
            segments: Arc::new(RwLock::new(SegmentChain::new(main_pid))),
            epoch: AtomicU32::new(0),
            pending_sync: Arc::new(Mutex::new(None)),
            flags,
            throttling: Mutex::new(None),
            dispatcher,
            last_syscall: Mutex::new(HashMap::new()),
        }
    }

    /// Handle checkpoint request from the target
    pub fn handle_checkpoint<'s, 'scope, 'env>(
        &'s self,
        pid: Pid,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        if pid == self.main.pid {
            info!("Main called checkpoint");

            let nr_dirty_pages = if self
                .flags
                .contains(CheckCoordinatorFlags::NO_NR_DIRTY_PAGES_LOGGING)
            {
                0
            } else {
                self.main.nr_dirty_pages()?
            };

            assert!(
                self.pending_sync.lock().is_none(),
                "Unexpected pending_sync state when handling checkpoint request"
            );

            let epoch_local = self.epoch.fetch_add(1, Ordering::SeqCst);

            if self.flags.contains(CheckCoordinatorFlags::DONT_FORK) {
                self.main.resume()?;
                return Ok(());
            }

            let clone_flags = CloneFlags::CLONE_PARENT | CloneFlags::CLONE_PTRACE;
            let clone_signal = None;

            let mut segments = self.segments.upgradable_read();

            if !is_finishing {
                let is_last_checkpoint_finalizing = segments.is_last_checkpoint_finalizing();
                let reference = self
                    .main
                    .clone_process(
                        clone_flags,
                        clone_signal,
                        restart_old_syscall,
                        restart_old_syscall || !is_last_checkpoint_finalizing,
                    )?
                    .as_owned();

                self.dispatcher.handle_checkpoint_created_pre(
                    pid,
                    segments.lookup_segment_main_mg().map(|s| s.nr),
                )?;

                if !is_last_checkpoint_finalizing {
                    let mut throttling = self.throttling.lock();

                    if let Some(throttler) = throttling.as_ref() {
                        panic!("Unexpected throttling state");
                    } else {
                        if let Some(throttler) =
                            self.dispatcher
                                .dispatch_throttle(nr_dirty_pages, &segments, self)
                        {
                            info!("Throttling");
                            *throttling = Some(throttler);
                        } else {
                            self.main.resume()?;
                        }
                    }
                } else {
                    self.main.resume()?;
                }

                let (checker, checkpoint) = if is_last_checkpoint_finalizing {
                    (reference, Checkpoint::initial(epoch_local, caller))
                } else {
                    (
                        reference
                            .clone_process(
                                clone_flags,
                                clone_signal,
                                restart_old_syscall,
                                restart_old_syscall,
                            )?
                            .as_owned(),
                        Checkpoint::subsequent(epoch_local, reference, nr_dirty_pages, caller),
                    )
                };

                self.dispatcher
                    .handle_checker_init(&ProcessLifetimeHookContext {
                        process: &checker,
                        check_coord: self,
                        scope,
                    });

                info!("New checkpoint: {:?}", checkpoint);
                segments.with_upgraded(|segments_mut| {
                    self.add_checkpoint(segments_mut, checkpoint, Some(checker))
                })?;
            } else {
                if !segments.is_last_checkpoint_finalizing() {
                    let reference = self
                        .main
                        .clone_process(
                            clone_flags,
                            clone_signal,
                            restart_old_syscall,
                            restart_old_syscall,
                        )?
                        .as_owned();

                    self.dispatcher.handle_checkpoint_created_pre(
                        pid,
                        segments.lookup_segment_main_mg().map(|s| s.nr),
                    )?;

                    self.main.resume()?;
                    let checkpoint =
                        Checkpoint::subsequent(epoch_local, reference, nr_dirty_pages, caller);

                    info!("New checkpoint: {:?}", checkpoint);
                    segments.with_upgraded(|segments_mut| {
                        self.add_checkpoint(segments_mut, checkpoint, None)
                    })?;
                } else {
                    info!("No-op checkpoint_fini");
                    self.main.resume();
                }
            }
        } else {
            let mut segments_rg = self.segments.upgradable_read();

            if let Some(segment_arc) = segments_rg.lookup_segment_checker_arc(pid) {
                info!("Checker called checkpoint");

                let mut segment = segment_arc.lock();

                if self.flags.contains(CheckCoordinatorFlags::NO_MEM_CHECK) {
                    segment.mark_as_checked(false).unwrap();

                    drop(segment);

                    segments_rg.with_upgraded(|segments_mut| {
                        self.cleanup_committed_segments(segments_mut)
                    })?;

                    drop(segments_rg);
                } else {
                    let segment_arc = segment_arc.clone();

                    scope.spawn(move || {
                        let mut segment = segment_arc.lock();

                        let mut outer_nr_dirty_pages = None;

                        match segment.check(
                            self.main.pid,
                            &self.dispatcher.get_ignored_pages(),
                            &self.dispatcher.get_extra_writable_ranges(),
                            self.dispatcher,
                        ) {
                            Ok((result, nr_dirty_pages)) => {
                                self.dispatcher.handle_segment_checked(&segment).unwrap();
                                outer_nr_dirty_pages = Some(nr_dirty_pages);

                                if result.is_err() {
                                    if self
                                        .flags
                                        .contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS)
                                    {
                                        warn!("Check fails");
                                    } else {
                                        error!("Check fails");
                                    }

                                    // self.main.dump_memory_maps();
                                } else {
                                    info!("Check passed");
                                }

                                segment.mark_as_checked(result.is_err()).unwrap();
                            }
                            Err(e) => {
                                error!("Failed to check: {:?}", e);
                                segment.mark_as_checked(true).unwrap();
                            }
                        }

                        drop(segment);

                        self.dispatcher
                            .handle_checker_fini(
                                outer_nr_dirty_pages,
                                &ProcessLifetimeHookContext {
                                    process: &Process::new(pid),
                                    check_coord: self,
                                    scope,
                                },
                            ) // TODO: process may have terminated
                            .unwrap(); // TODO: error handling

                        let mut segments = self.segments.upgradable_read();
                        segments.with_upgraded(|segments| {
                            self.cleanup_committed_segments(segments).unwrap();
                        });
                        // TODO: error handling
                    });
                }
            } else {
                panic!("Unexpected PID")
            };
        };

        // if let Some(segment) = self.segments.get_segment_by_checker_pid(pid) {
        //     info!("Checker called checkpoint");

        // } else {
        //     panic!("invalid pid");
        // }

        Ok(())
    }

    pub fn handle_sync(&self) -> Result<()> {
        assert!(
            self.throttling.lock().is_none(),
            "Unexpected throttling state when checkpoint_sync is called"
        );

        let segments = self.segments.upgradable_read();

        if let Some(last_segment) = segments.last_segment() {
            let epoch = last_segment
                .lock()
                .status
                .checkpoint_end()
                .ok_or(Error::ReturnedToUser(
                    Errno::EINVAL,
                    "Attempt to sync before checkpoint_fini is called".to_string(),
                ))?
                .epoch;

            let mut pending_sync = self.pending_sync.lock();

            assert!(
                pending_sync.is_none(),
                "Unexpected pending_sync state when checkpoint_sync is called"
            );
            pending_sync.insert(epoch);
        } else {
            self.main.resume()?;
        }

        Ok(())
    }

    fn cleanup_committed_segments(&self, segments: &mut SegmentChain) -> Result<()> {
        let ignore_errors = self
            .flags
            .contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS);

        segments.cleanup_committed_segments(ignore_errors, |segment| {
            self.dispatcher.handle_segment_removed(segment)
        })?;

        let mut pending_sync = self.pending_sync.lock();

        if let Some(epoch) = pending_sync.as_ref() {
            assert!(
                self.throttling.lock().is_none(),
                "Unexpected throttling state when pending_sync is active"
            );

            if let Some(front) = segments.first_segment() {
                if front.lock().checkpoint_start.epoch > *epoch {
                    pending_sync.take().map(drop);
                    self.main.resume()?;
                }
            } else {
                pending_sync.take().map(drop);
                self.main.resume()?;
            }
        } else {
            let mut throttling = self.throttling.lock();

            if let Some(&throttler) = throttling.as_ref() {
                if throttler.should_unthrottle(segments, self) {
                    *throttling = None;
                    self.main.resume()?;
                    info!("Unthrottled");
                } else {
                    if segments.nr_live_segments() == 0 {
                        panic!(
                            "Deadlock detected: unthrottle not called after the number of live segments reaching zero"
                        );
                    }
                }
            }
        }

        // if self.options.max_nr_live_segments != 0
        //     && self.segments.len() <= self.options.max_nr_live_segments
        //     && self
        //         .throttling
        //         .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
        //         .is_ok()
        // {
        //     info!("Resuming main");
        //     self.main.resume()?;
        // }

        Ok(())
    }

    /// Create a new checkpoint and kick off the checker of the previous checkpoint if needed.
    fn add_checkpoint(
        &self,
        segments: &mut SegmentChain,
        checkpoint: Checkpoint,
        checker: Option<OwnedProcess>,
    ) -> Result<()> {
        segments.add_checkpoint(
            checkpoint,
            checker,
            |last_segment, checkpoint| {
                if self.flags.contains(CheckCoordinatorFlags::DONT_RUN_CHECKER) {
                    last_segment.mark_as_checked(false).unwrap();
                    Ok(true)
                } else {
                    self.dispatcher
                        .handle_segment_ready(last_segment, checkpoint.caller)?;

                    last_segment.checker().unwrap().resume()?;
                    Ok(false)
                }
            },
            |segment| self.dispatcher.handle_segment_created(segment),
            |segment| self.dispatcher.handle_segment_chain_closed(segment),
            |segments| self.cleanup_committed_segments(segments),
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

    /// Check if any checker has errors unless IGNORE_CHECK_ERRORS is set.
    pub fn has_errors(&self) -> bool {
        !self
            .flags
            .contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS)
            && self.segments.read().has_errors()
    }

    pub fn handle_syscall_entry<'s, 'scope, 'env>(
        &'s self,
        pid: Pid,
        sysno: Sysno,
        args: SyscallArgs,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let syscall = reverie_syscalls::Syscall::from_raw(sysno, args);
        let process = Process::new(pid);

        let segments = self.segments.upgradable_read();

        let handler_context = HandlerContext {
            process: &process,
            segments: &segments,
            check_coord: self,
            scope,
        };

        let mut skip_ptrace_syscall = false;

        info!("[PID {: >8}] Syscall: {:}", pid, syscall.display(&process));

        self.last_syscall.lock().insert(pid, syscall);

        if matches!(
            self.dispatcher
                .handle_standard_syscall_entry(&syscall, &handler_context)?,
            SyscallHandlerExitAction::ContinueInferior
        ) {
            ptrace::syscall(pid, None)?;
            return Ok(());
        }

        if let Some((active_segment, is_main)) = segments.lookup_segment_arc(pid) {
            let mut active_segment = active_segment.lock();

            if is_main {
                // main syscall entry
                let result = self.dispatcher.handle_standard_syscall_entry_main(
                    &syscall,
                    &mut active_segment,
                    &handler_context,
                )?;

                if active_segment.ongoing_syscall.is_some() {
                    return Err(Error::UnexpectedSyscall(EventFlags::empty()));
                }

                match result {
                    StandardSyscallEntryMainHandlerExitAction::NextHandler => {
                        // Main syscall entry, record memory read by the syscall
                        let may_read = syscall.may_read(&process).ok().map(|slices| {
                            slices
                                .iter()
                                .map(|slice| RemoteIoVec {
                                    base: unsafe { slice.as_ptr() as _ },
                                    len: slice.len(),
                                })
                                .collect::<Vec<RemoteIoVec>>()
                                .into_boxed_slice()
                        });

                        let may_write = syscall.may_write(&process).ok().map(|slices| {
                            slices
                                .iter()
                                .map(|slice| RemoteIoVec {
                                    base: unsafe { slice.as_ptr() as _ },
                                    len: slice.len(),
                                })
                                .collect::<Vec<RemoteIoVec>>()
                                .into_boxed_slice()
                        });

                        match (may_read, may_write) {
                            (Some(may_read), Some(may_write)) => {
                                // we know the exact memory r/w of the syscall
                                active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                                    syscall,
                                    kind: SavedIncompleteSyscallKind::KnownMemoryRAndWRange {
                                        mem_read: SavedMemory::save(&process, &may_read)?,
                                        mem_written_ranges: may_write,
                                    },
                                    exit_action: SyscallExitAction::ReplicateMemoryWrites,
                                });
                            }
                            _ => {
                                // otherwise, take a full checkpoint right before the syscall and another right after the syscall
                                active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                                    syscall,
                                    kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                                    exit_action: SyscallExitAction::Checkpoint,
                                });

                                // TODO: take a checkpoint now
                                todo!("take a full checkpoint");
                            }
                        }
                    }
                    StandardSyscallEntryMainHandlerExitAction::StoreSyscall(
                        saved_incomplete_syscall,
                    ) => {
                        active_segment.ongoing_syscall = Some(saved_incomplete_syscall);
                    }
                    StandardSyscallEntryMainHandlerExitAction::StoreSyscallAndCheckpoint(
                        saved_incomplete_syscall,
                    ) => {
                        active_segment.ongoing_syscall = Some(saved_incomplete_syscall);
                        drop(active_segment);
                        drop(segments);

                        self.handle_checkpoint(pid, true, true, CheckpointCaller::Shell, scope)?;
                        skip_ptrace_syscall = true;
                    }
                }
            } else {
                // checker syscall entry
                let result = self.dispatcher.handle_standard_syscall_entry_checker(
                    &syscall,
                    &mut active_segment,
                    &handler_context,
                )?;

                match result {
                    StandardSyscallEntryCheckerHandlerExitAction::NextHandler => {
                        // info!("Checker syscall entry");
                        // dbg!(&active_segment);
                        // we are one of the checker processes
                        if let Some(saved_syscall) = active_segment.syscall_log.front() {
                            assert_eq!(saved_syscall.syscall.into_parts(), syscall.into_parts());

                            match &saved_syscall.kind {
                                SavedSyscallKind::UnknownMemoryRw => {
                                    todo!("take a full checkpoint");
                                }
                                SavedSyscallKind::KnownMemoryRw { mem_read, .. } => {
                                    // compare memory read by the syscall
                                    assert!(mem_read.compare(&process)?); // TODO: handle this more gracefully
                                }
                            }
                        } else {
                            return Err(Error::UnexpectedSyscall(EventFlags::IS_EXCESS));
                        }

                        active_segment
                            .checker()
                            .unwrap()
                            .modify_registers_with(|regs| regs.with_syscall_skipped())?;
                    }
                    StandardSyscallEntryCheckerHandlerExitAction::ContinueInferior => (),
                    StandardSyscallEntryCheckerHandlerExitAction::Checkpoint => {
                        drop(active_segment);
                        drop(segments);

                        self.handle_checkpoint(pid, true, false, CheckpointCaller::Shell, scope)?;
                        skip_ptrace_syscall = true;
                    }
                }
            }
        }

        if !skip_ptrace_syscall {
            ptrace::syscall(pid, None).unwrap();
        }

        Ok(())
    }

    pub fn handle_syscall_exit<'s, 'scope, 'env>(
        &'s self,
        pid: Pid,
        ret_val: isize,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let mut process = Process::new(pid);
        let mut skip_ptrace_syscall = false;

        let segments = self.segments.upgradable_read();

        let last_syscall = self
            .last_syscall
            .lock()
            .remove(&pid)
            .ok_or(Error::UnexpectedSyscall(EventFlags::IS_INVALID))?;

        let handler_context = HandlerContext {
            process: &process,
            segments: &segments,
            check_coord: self,
            scope,
        };

        if matches!(
            self.dispatcher.handle_standard_syscall_exit(
                ret_val,
                &last_syscall,
                &handler_context,
            )?,
            SyscallHandlerExitAction::ContinueInferior
        ) {
            ptrace::syscall(pid, None)?;
            return Ok(());
        }

        if let Some((active_segment, is_main)) = segments.lookup_segment_arc(pid) {
            let mut active_segment = active_segment.lock();

            if is_main {
                // Main syscall exit
                let saved_incomplete_syscall = active_segment
                    .ongoing_syscall
                    .take()
                    .ok_or(Error::UnexpectedSyscall(EventFlags::IS_INVALID))?;

                let (sysno, args) = saved_incomplete_syscall.syscall.into_parts();

                let saved_syscall = match saved_incomplete_syscall.exit_action {
                    SyscallExitAction::ReplicateMemoryWrites => {
                        // store memory contents that are potentially written during the syscall
                        let mem_written = match &saved_incomplete_syscall.kind {
                            SavedIncompleteSyscallKind::KnownMemoryRAndWRange {
                                mem_read,
                                mem_written_ranges,
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
                            &mut active_segment,
                            &handler_context,
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

                active_segment.syscall_log.push_back(saved_syscall);
            } else {
                // Checker syscall exit

                let saved_syscall = active_segment
                    .syscall_log
                    .pop_front()
                    .ok_or(Error::UnexpectedSyscall(EventFlags::IS_INVALID))?;

                let (sysno, args) = saved_syscall.syscall.into_parts();

                match saved_syscall.exit_action {
                    SyscallExitAction::ReplicateMemoryWrites => {
                        match saved_syscall.kind {
                            SavedSyscallKind::KnownMemoryRw { mem_written, .. } => {
                                active_segment.checker().unwrap().modify_registers_with(
                                    |regs| regs.with_syscall_ret_val(saved_syscall.ret_val),
                                )?;
                                mem_written.dump(&mut process)?;
                            }
                            _ => panic!(),
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
                            &mut active_segment,
                            &handler_context,
                        )?;

                        if matches!(result, SyscallHandlerExitAction::NextHandler) {
                            panic!("unhandled custom syscall during syscall exit");
                        }
                    }
                }
            }
        } else {
            // outside protected region
            if let Some(last_segment) = segments.last_segment() {
                let mut last_segment = last_segment.lock();

                if let Some(ongoing_syscall) = last_segment.ongoing_syscall.take() {
                    assert_eq!(pid, self.main.pid);
                    assert_eq!(ongoing_syscall.exit_action, SyscallExitAction::Checkpoint);
                    drop(last_segment);

                    // restore registers as if we haven't modified any flags
                    self.main.modify_registers_with(|regs| {
                        regs.with_syscall_args(ongoing_syscall.syscall.into_parts().1)
                    });

                    drop(segments);

                    self.handle_checkpoint(pid, false, false, CheckpointCaller::Shell, scope)?;
                    skip_ptrace_syscall = true;
                }
            }
        }

        if !skip_ptrace_syscall {
            ptrace::syscall(pid, None)?;
        }

        Ok(())
    }

    pub fn handle_signal<'s, 'scope, 'env>(
        &'s self,
        pid: Pid,
        sig: Signal,
        scope: &'scope Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
    {
        let process = Process::new(pid);

        let segments = self.segments.read();

        let result = self.dispatcher.handle_signal(
            sig,
            &HandlerContext {
                process: &process,
                segments: &segments,
                check_coord: self,
                scope,
            },
        )?;

        match result {
            SignalHandlerExitAction::SkipPtraceSyscall => (),
            SignalHandlerExitAction::SuppressSignalAndContinueInferior => {
                ptrace::syscall(pid, None)?;
            }
            SignalHandlerExitAction::NextHandler => {
                info!("[PID {: >8}] Signal: {:}", pid, sig);
                ptrace::syscall(pid, sig)?;
            }
            SignalHandlerExitAction::ContinueInferior => {
                ptrace::syscall(pid, sig)?;
            }
            SignalHandlerExitAction::Checkpoint => {
                drop(segments);
                self.handle_checkpoint(pid, false, false, CheckpointCaller::Shell, scope)?;
            }
        }

        Ok(())
    }
}
