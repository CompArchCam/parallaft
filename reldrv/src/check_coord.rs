use std::arch::x86_64::{__cpuid_count, __rdtscp, _rdtsc};
use std::collections::HashMap;
use std::mem::MaybeUninit;
use std::sync::atomic::{AtomicBool, AtomicU32, Ordering};
use std::sync::Arc;

use bitflags::bitflags;

use log::{error, info, warn};
use nix::sys::ptrace;
use nix::sys::signal::Signal;
use nix::sys::uio::RemoteIoVec;

use nix::{sched::CloneFlags, unistd::Pid};

use parking_lot::{Mutex, RwLock};

use reverie_syscalls::{
    Addr, AddrMut, Displayable, MapFlags, MemoryAccess, Syscall, SyscallArgs, SyscallInfo, Sysno,
};

use crate::dispatcher::Dispatcher;
use crate::inferior_rtlib::client_control;
use crate::process::{OwnedProcess, Process};
use crate::saved_syscall::{
    SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedMemory, SavedSyscallKind,
    SyscallExitAction,
};
use crate::segments::{Checkpoint, CheckpointCaller, SavedTrapEvent, SegmentChain};
use crate::stats::Statistics;
use crate::syscall_handlers::{HandlerContext, SyscallHandlerExitAction};
use reverie_syscalls::may_rw::{SyscallMayRead, SyscallMayWrite};

pub struct CheckCoordinator<'a> {
    pub segments: Arc<SegmentChain>,
    pub main: Arc<OwnedProcess>,
    pub epoch: AtomicU32,
    throttling: Arc<AtomicBool>,
    pending_sync: Arc<Mutex<Option<u32>>>,
    stats: Arc<Statistics>,
    client_control_addr: Arc<RwLock<Option<usize>>>,
    options: CheckCoordinatorOptions,
    hooks: CheckCoordinatorHooks,
    dispatcher: &'a Dispatcher<'a>,
    last_syscall: Mutex<HashMap<Pid, Syscall>>,
}

bitflags! {
    pub struct CheckCoordinatorFlags: u32 {
        const SYNC_MEM_CHECK = 0b00000001;
        const NO_MEM_CHECK = 0b00000010;
        const DONT_RUN_CHECKER = 0b00000100;
        const DONT_CLEAR_SOFT_DIRTY = 0b00001000;
        const DONT_FORK = 0b00100000;
        const IGNORE_CHECK_ERRORS = 0b01000000;
    }
}

pub struct CheckCoordinatorOptions {
    pub max_nr_live_segments: usize,
    pub flags: CheckCoordinatorFlags,
}

impl Default for CheckCoordinatorOptions {
    fn default() -> Self {
        Self {
            max_nr_live_segments: 0,
            flags: CheckCoordinatorFlags::empty(),
        }
    }
}

#[allow(unused)]
impl CheckCoordinatorOptions {
    pub fn with_max_nr_live_segments(mut self, max_nr_live_segments: usize) -> Self {
        self.max_nr_live_segments = max_nr_live_segments;
        self
    }

    pub fn with_flags(mut self, flags: CheckCoordinatorFlags) -> Self {
        self.flags = flags;
        self
    }
}

pub struct CheckCoordinatorHooks {
    pub on_checker_created: Box<dyn Fn(&OwnedProcess) -> ()>,
}

impl Default for CheckCoordinatorHooks {
    fn default() -> Self {
        Self {
            on_checker_created: Box::new(|_| ()),
        }
    }
}

impl CheckCoordinatorHooks {
    pub fn with_on_checker_created(mut self, f: impl Fn(&OwnedProcess) -> () + 'static) -> Self {
        self.on_checker_created = Box::new(f);
        self
    }
}

#[allow(unused)]
impl<'a> CheckCoordinator<'a> {
    pub fn new(
        main: OwnedProcess,
        options: CheckCoordinatorOptions,
        hooks: CheckCoordinatorHooks,
        dispatcher: &'a Dispatcher,
    ) -> Self {
        // main.pid
        let main_pid = main.pid;
        Self {
            main: Arc::new(main),
            segments: Arc::new(SegmentChain::new(main_pid)),
            epoch: AtomicU32::new(0),
            pending_sync: Arc::new(Mutex::new(None)),
            stats: Arc::new(Statistics::new()),
            client_control_addr: Arc::new(RwLock::new(None)),
            options,
            hooks,
            throttling: Arc::new(AtomicBool::new(false)),
            dispatcher,
            last_syscall: Mutex::new(HashMap::new()),
        }
    }

    /// Handle checkpoint request from the target
    pub fn handle_checkpoint(
        &self,
        pid: Pid,
        is_finishing: bool,
        restart_old_syscall: bool,
        caller: CheckpointCaller,
    ) {
        if pid == self.main.pid {
            info!("Main called checkpoint");
            let epoch_local = self.epoch.fetch_add(1, Ordering::SeqCst);

            if self
                .options
                .flags
                .contains(CheckCoordinatorFlags::DONT_FORK)
            {
                self.main.resume();
                return;
            }

            let clone_flags = CloneFlags::CLONE_PARENT | CloneFlags::CLONE_PTRACE;
            let clone_signal = None;

            if !is_finishing {
                let reference = self
                    .main
                    .clone_process(clone_flags, clone_signal, restart_old_syscall)
                    .as_owned();

                if !self
                    .options
                    .flags
                    .contains(CheckCoordinatorFlags::DONT_CLEAR_SOFT_DIRTY)
                {
                    self.main.clear_dirty_page_bits();
                }

                if self.options.max_nr_live_segments == 0
                    || self.segments.len() < self.options.max_nr_live_segments
                {
                    self.main.resume();
                } else {
                    self.throttling
                        .compare_exchange(false, true, Ordering::SeqCst, Ordering::SeqCst)
                        .unwrap();
                    info!("Too many live segments. Pausing the main process");
                }

                let (checker, checkpoint) = match self.segments.is_last_checkpoint_finalizing() {
                    true => (reference, Checkpoint::new_initial(epoch_local, caller)),
                    false => (
                        reference
                            .clone_process(clone_flags, clone_signal, restart_old_syscall)
                            .as_owned(),
                        Checkpoint::new(epoch_local, reference, caller),
                    ),
                };

                (self.hooks.on_checker_created)(&checker);

                if !self
                    .options
                    .flags
                    .contains(CheckCoordinatorFlags::DONT_CLEAR_SOFT_DIRTY)
                {
                    checker.clear_dirty_page_bits();
                }

                info!("New checkpoint: {:?}", checkpoint);
                self.add_checkpoint(checkpoint, Some(checker));
            } else {
                if !self.segments.is_last_checkpoint_finalizing() {
                    let reference = self
                        .main
                        .clone_process(clone_flags, clone_signal, restart_old_syscall)
                        .as_owned();
                    self.main.resume();
                    let checkpoint = Checkpoint::new(epoch_local, reference, caller);

                    info!("New checkpoint: {:?}", checkpoint);
                    self.add_checkpoint(checkpoint, None);
                } else {
                    info!("No-op checkpoint_fini");
                    self.main.resume();
                }
            }
        } else if let Some(segment) = self.segments.get_segment_by_checker_pid(pid) {
            info!("Checker called checkpoint");

            if self
                .options
                .flags
                .contains(CheckCoordinatorFlags::NO_MEM_CHECK)
            {
                segment.lock().mark_as_checked(false).unwrap();
                Self::cleanup_committed_segments(
                    &self.main,
                    &mut self.pending_sync.lock(),
                    &self.segments,
                    self.options.max_nr_live_segments,
                    self.options
                        .flags
                        .contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS),
                    &self.throttling,
                );
            } else if self
                .options
                .flags
                .contains(CheckCoordinatorFlags::SYNC_MEM_CHECK)
            {
                todo!();
                // let mut segment = segment.lock();
                // let (result, nr_dirty_pages) = segment.check().unwrap();
                // let mut avg_nr_dirty_pages = self.avg_nr_dirty_pages.lock();

                // let alpha = 1.0 / segment.checkpoint_start.epoch as f64;
                // info!("alpha = {}", alpha);

                // *avg_nr_dirty_pages =
                //     *avg_nr_dirty_pages * (1.0 - alpha) + (nr_dirty_pages as f64) * alpha;

                // drop(avg_nr_dirty_pages);
                // drop(segment);

                // if !result {
                //     panic!("check fails");
                // }
                // info!("Check passed");
                // Self::cleanup_committed_segments(
                //     self.pending_sync.lock().deref_mut(),
                //     self.segments.write().deref_mut(),
                // );
            } else {
                let segment = segment.clone();
                let segments = self.segments.clone();

                let pending_sync = self.pending_sync.clone();
                let stats = self.stats.clone();
                let client_control_addr = self.client_control_addr.clone();

                let main = self.main.clone();
                let flags = self.options.flags;
                let max_nr_live_segments = self.options.max_nr_live_segments;
                let throttling = self.throttling.clone();

                std::thread::Builder::new()
                    .name(format!("checker-memcmp-{}", pid))
                    .spawn(move || {
                        let mut segment = segment.lock();
                        let client_control_addr = client_control_addr.read();
                        let ignored_pages = client_control_addr
                            .as_ref()
                            .map_or(vec![], |a| vec![*a as usize]);

                        let (result, nr_dirty_pages) =
                            segment.check(ignored_pages.as_slice()).unwrap();

                        stats.update_nr_dirty_pages(nr_dirty_pages);

                        drop(segment);

                        if !result {
                            if flags.contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS) {
                                warn!("Check fails");
                            } else {
                                error!("Check fails");
                            }
                        } else {
                            info!("Check passed");
                        }
                        Self::cleanup_committed_segments(
                            &main,
                            &mut pending_sync.lock(),
                            &segments,
                            max_nr_live_segments,
                            flags.contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS),
                            &throttling,
                        );
                    });
            }
        } else {
            panic!("invalid pid");
        }
    }

    pub fn handle_sync(&self) {
        if let Some(last_segment) = self.segments.get_last_segment() {
            let epoch = last_segment
                .lock()
                .status
                .checkpoint_end()
                .expect("Attempt to sync before checkpoint_fini is called")
                .epoch;

            let mut pending_sync = self.pending_sync.lock();

            assert!(pending_sync.is_none());
            pending_sync.insert(epoch);
        } else {
            self.main.resume();
        }
    }

    fn cleanup_committed_segments(
        main: &Process,
        pending_sync: &mut Option<u32>,
        segments: &SegmentChain,
        max_nr_live_segments: usize,
        ignore_errors: bool,
        throttling: &AtomicBool,
    ) {
        let old_len = segments.len();

        segments.cleanup_committed_segments(ignore_errors);

        if let Some(epoch) = pending_sync.as_ref() {
            if let Some(front) = segments.get_first_segment() {
                if front.lock().checkpoint_start.epoch > *epoch {
                    pending_sync.take().map(drop);
                    main.resume();
                }
            } else {
                pending_sync.take().map(drop);
                main.resume();
            }
        }

        // dbg!(old_len);
        // dbg!(max_nr_live_segments);
        // dbg!(segments.len());

        if max_nr_live_segments != 0
            && segments.len() <= max_nr_live_segments
            && throttling
                .compare_exchange(true, false, Ordering::SeqCst, Ordering::SeqCst)
                .is_ok()
        {
            info!("Resuming main");
            main.resume();
        }
    }

    /// Create a new checkpoint and kick off the checker of the previous checkpoint if needed.
    fn add_checkpoint(&self, checkpoint: Checkpoint, checker: Option<OwnedProcess>) {
        self.segments.add_checkpoint(
            checkpoint,
            checker,
            |last_segment, checkpoint| {
                if self
                    .options
                    .flags
                    .contains(CheckCoordinatorFlags::DONT_RUN_CHECKER)
                {
                    last_segment.mark_as_checked(false);
                    true
                } else {
                    let last_checker = last_segment.checker().unwrap();

                    // patch the checker's client_control struct
                    if let Some(base_address) = self.client_control_addr.read().as_ref() {
                        let this_reference = checkpoint.reference().unwrap();
                        let mut ctl =
                            client_control::read(this_reference.pid, *base_address).unwrap();
                        ctl.role = if checkpoint.caller == CheckpointCaller::Child {
                            client_control::CliRole::Checker
                        } else {
                            client_control::CliRole::Nop
                        };

                        client_control::write(&ctl, last_checker.pid, *base_address).unwrap();
                    }

                    last_checker.resume();
                    false
                }
            },
            || {
                Self::cleanup_committed_segments(
                    &self.main,
                    &mut self.pending_sync.lock(),
                    &self.segments,
                    self.options.max_nr_live_segments,
                    self.options
                        .flags
                        .contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS),
                    &self.throttling,
                );
            },
        );
    }

    /// Get the current epoch.
    pub fn epoch(&self) -> u32 {
        self.epoch.load(Ordering::SeqCst)
    }

    /// Get the average number of dirty pages per iteration.
    pub fn avg_nr_dirty_pages(&self) -> f64 {
        self.stats.avg_nr_dirty_pages()
    }

    /// Check if all checkers has finished.
    pub fn is_all_finished(&self) -> bool {
        self.segments.is_empty()
    }

    /// Check if any checker has errors unless IGNORE_CHECK_ERRORS is set.
    pub fn has_errors(&self) -> bool {
        !self
            .options
            .flags
            .contains(CheckCoordinatorFlags::IGNORE_CHECK_ERRORS)
            && self.segments.has_errors()
    }

    pub fn set_client_control_addr(&self, base_address: usize) {
        self.client_control_addr.write().insert(base_address);
    }

    pub fn handle_syscall_entry(&self, pid: Pid, sysno: Sysno, args: SyscallArgs) {
        let syscall = reverie_syscalls::Syscall::from_raw(sysno, args);
        let process = Process::new(pid);
        let mut skip_ptrace_syscall = false;

        info!("[PID {: >8}] Syscall: {:}", pid, syscall.display(&process));

        self.last_syscall.lock().insert(pid, syscall);

        if matches!(
            self.dispatcher.handle_standard_syscall_entry(
                &syscall,
                &HandlerContext {
                    process: &process,
                    check_coord: self,
                },
            ),
            SyscallHandlerExitAction::Noop
        ) {
            return;
        }

        if matches!(
            syscall,
            Syscall::Fork(_) | Syscall::Vfork(_) | Syscall::Clone(_) | Syscall::Clone3(_)
        ) {
            panic!("fork/vfork/clone/clone3 is disallowed");
        }

        if let Some((active_segment, is_main)) = self.segments.get_active_segment_by_pid(pid) {
            match syscall {
                Syscall::Execve(_) | Syscall::Execveat(_) => {
                    panic!("Execve(at) is disallowed in protected regions");
                }
                Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                    self.handle_checkpoint(pid, true, true, CheckpointCaller::Shell);
                    return; // skip ptrace::syscall
                }
                Syscall::ArchPrctl(_)
                | Syscall::Brk(_)
                | Syscall::Mprotect(_)
                | Syscall::Munmap(_) => {
                    let mut active_segment = active_segment.lock();
                    // replicate the syscall in the checker processes

                    if is_main {
                        assert!(active_segment.ongoing_syscall.is_none());

                        active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                            syscall,
                            kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                            exit_action: SyscallExitAction::ReplicateSyscall,
                        });
                    } else {
                        let saved_syscall = active_segment
                            .syscall_log
                            .front()
                            .expect("spurious syscall made by checker");

                        assert_eq!(saved_syscall.syscall.into_parts(), syscall.into_parts());
                    }

                    // TODO: handle execve aslr
                }
                Syscall::Mmap(mut mmap) => {
                    let mut active_segment = active_segment.lock();

                    if is_main {
                        // main process
                        assert!(active_segment.ongoing_syscall.is_none());

                        // HACK
                        // if mmap.flags().contains(MapFlags::MAP_SHARED) {
                        //     mmap = mmap.with_prot(mmap.prot() & !ProtFlags::PROT_WRITE);
                        // }

                        mmap = mmap.with_flags(
                            (mmap.flags() & !MapFlags::MAP_SHARED) | MapFlags::MAP_PRIVATE, // TODO: MAP_SHARED_VALIDATE
                        );

                        // if mmap.flags().contains(MapFlags::MAP_SHARED)
                        //     && mmap.prot().contains(ProtFlags::PROT_WRITE)
                        // {
                        //     panic!("Unsupported MAP_SHARED and PROT_WRITE combination");
                        // }

                        if !mmap.flags().contains(MapFlags::MAP_ANONYMOUS) {
                            // File-backed mmap
                            assert!(mmap.fd() >= 0);

                            active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                                syscall,
                                kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                                exit_action: SyscallExitAction::Checkpoint,
                            });

                            drop(active_segment);

                            self.main.modify_registers_with(|regs| {
                                regs.with_syscall_args(mmap.into_parts().1)
                            });

                            info!("Main mmap checkpoint fini");
                            self.handle_checkpoint(pid, true, true, CheckpointCaller::Shell);
                            skip_ptrace_syscall = true;
                        } else {
                            self.main.modify_registers_with(|regs| {
                                regs.with_syscall_args(mmap.into_parts().1)
                            });

                            active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                                syscall,
                                kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                                exit_action: SyscallExitAction::Custom,
                            });
                        }
                    } else {
                        // checker process
                        // use MAP_FIXED, mapping exactly the same address that the main process did

                        if !mmap.flags().contains(MapFlags::MAP_ANONYMOUS) {
                            info!("Checker mmap checkpoint fini");
                            // File-backed mmap
                            assert!(mmap.fd() >= 0);

                            drop(active_segment);

                            self.handle_checkpoint(pid, true, false, CheckpointCaller::Shell);
                            skip_ptrace_syscall = true;
                        } else {
                            let saved_syscall = active_segment
                                .syscall_log
                                .front()
                                .expect("spurious syscall made by checker");

                            assert_eq!(saved_syscall.syscall.into_parts(), syscall.into_parts());

                            if saved_syscall.ret_val != nix::libc::MAP_FAILED as _ {
                                // rewrite only if mmap has succeeded
                                let mmap = mmap
                                    .with_addr(Addr::from_raw(saved_syscall.ret_val as _))
                                    .with_flags(mmap.flags() | MapFlags::MAP_FIXED_NOREPLACE);

                                let (new_sysno, new_args) = mmap.into_parts();
                                active_segment
                                    .checker()
                                    .unwrap()
                                    .modify_registers_with(|regs| {
                                        regs.with_sysno(new_sysno).with_syscall_args(new_args)
                                    })
                            }
                        }
                    }
                }
                Syscall::Mremap(mut mremap) => {
                    let mut active_segment = active_segment.lock();

                    if is_main {
                        active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                            syscall,
                            kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                            exit_action: SyscallExitAction::Custom,
                        });
                    } else {
                        let saved_syscall = active_segment
                            .syscall_log
                            .front()
                            .expect("spurious syscall made by checker");

                        assert_eq!(saved_syscall.syscall.into_parts(), syscall.into_parts());

                        // rewrite only if mmap has succeeded
                        if saved_syscall.ret_val != nix::libc::MAP_FAILED as _ {
                            // rewrite only if the original call moves the address
                            if mremap.flags() & nix::libc::MREMAP_MAYMOVE as usize != 0 {
                                let addr_raw = mremap.addr().map(|a| a.as_raw()).unwrap_or(0);

                                if addr_raw == saved_syscall.ret_val as _ {
                                    mremap = mremap.with_flags(
                                        mremap.flags() & !nix::libc::MREMAP_MAYMOVE as usize,
                                    );
                                } else {
                                    mremap = mremap
                                        .with_new_addr(AddrMut::from_ptr(
                                            saved_syscall.ret_val as _,
                                        ))
                                        .with_flags(
                                            mremap.flags() | nix::libc::MREMAP_FIXED as usize,
                                        );
                                }
                            }

                            let (new_sysno, new_args) = mremap.into_parts();
                            active_segment
                                .checker()
                                .unwrap()
                                .modify_registers_with(|regs| {
                                    regs.with_sysno(new_sysno).with_syscall_args(new_args)
                                });
                        }
                    }
                }
                _ => {
                    let mut active_segment = active_segment.lock();

                    // replicate memory written by the syscall in the checker
                    if is_main {
                        // info!("Main syscall entry");
                        // we are the main process
                        assert!(active_segment.ongoing_syscall.is_none());

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
                                        mem_read: SavedMemory::save(&process, &may_read).unwrap(),
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

                        // dbg!(active_segment);
                    } else {
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
                                    assert!(mem_read.compare(&process).unwrap());
                                }
                            }
                        } else {
                            panic!("spurious syscall made by checker {:}", pid);
                        }

                        active_segment
                            .checker()
                            .unwrap()
                            .modify_registers_with(|regs| regs.with_syscall_skipped());
                    }
                }
            }
        };

        if !skip_ptrace_syscall {
            ptrace::syscall(pid, None).unwrap();
        }
    }

    pub fn handle_syscall_exit(&self, pid: Pid, ret_val: isize) {
        let mut process = Process::new(pid);
        let mut skip_ptrace_syscall = false;

        let last_syscall = self.last_syscall.lock().remove(&pid).unwrap();

        if matches!(
            self.dispatcher.handle_standard_syscall_exit(
                ret_val,
                &last_syscall,
                &HandlerContext {
                    process: &process,
                    check_coord: self,
                },
            ),
            SyscallHandlerExitAction::Noop
        ) {
            return;
        }

        self.segments
            .get_active_segment_with(pid, |active_segment, is_main| {
                if is_main {
                    // we are the main process
                    let saved_incomplete_syscall = active_segment.ongoing_syscall.take().unwrap();
                    let (sysno, args) = saved_incomplete_syscall.syscall.into_parts();

                    let saved_syscall = match saved_incomplete_syscall.exit_action {
                        SyscallExitAction::ReplicateMemoryWrites => {
                            // store memory contents that are potentially written during the syscall
                            let mem_written = match &saved_incomplete_syscall.kind {
                                SavedIncompleteSyscallKind::KnownMemoryRAndWRange {
                                    mem_read,
                                    mem_written_ranges,
                                } => SavedMemory::save(&process, &mem_written_ranges).unwrap(),
                                _ => panic!(),
                            };

                            saved_incomplete_syscall.upgrade(ret_val, Some(mem_written))
                        }
                        SyscallExitAction::ReplicateSyscall => {
                            saved_incomplete_syscall.upgrade(ret_val, None)
                        }
                        SyscallExitAction::Custom => {
                            match saved_incomplete_syscall.syscall {
                                Syscall::Mmap(_) | Syscall::Mremap(_) => {
                                    // restore registers as if we haven't modified mmap/mremap flags
                                    active_segment
                                        .checker()
                                        .unwrap()
                                        .modify_registers_with(|regs| regs.with_syscall_args(args));
                                }
                                _ => panic!("unhandled custom syscall during syscall exit"),
                            }
                            saved_incomplete_syscall.upgrade(ret_val, None)
                        }
                        SyscallExitAction::Checkpoint => {
                            todo!("take a full checkpoint");
                        }
                    };

                    active_segment.syscall_log.push_back(saved_syscall);
                    // info!("Main syscall exit");
                    // dbg!(&active_segment);
                } else {
                    // info!("Checker syscall exit");
                    // dbg!(&active_segment);
                    // we are one of the checker processes
                    let saved_syscall = active_segment.syscall_log.pop_front().unwrap();
                    let (sysno, args) = saved_syscall.syscall.into_parts();

                    match saved_syscall.exit_action {
                        SyscallExitAction::ReplicateMemoryWrites => {
                            match saved_syscall.kind {
                                SavedSyscallKind::KnownMemoryRw { mem_written, .. } => {
                                    active_segment.checker().unwrap().modify_registers_with(
                                        |regs| regs.with_syscall_ret_val(saved_syscall.ret_val),
                                    );
                                    mem_written.dump(&mut process).unwrap();
                                }
                                _ => panic!(),
                            }
                        }
                        SyscallExitAction::ReplicateSyscall => {
                            assert_eq!(ret_val, saved_syscall.ret_val);
                        }
                        SyscallExitAction::Checkpoint => todo!("take a full checkpoint"),
                        SyscallExitAction::Custom => {
                            assert_eq!(ret_val, saved_syscall.ret_val);

                            match saved_syscall.syscall {
                                Syscall::Mmap(_) | Syscall::Mremap(_) => {
                                    // restore registers as if we haven't modified mmap/mremap flags
                                    active_segment
                                        .checker()
                                        .unwrap()
                                        .modify_registers_with(|regs| regs.with_syscall_args(args));
                                }
                                _ => panic!("unhandled custom syscall during syscall exit"),
                            }
                        }
                    }
                }
            })
            .unwrap_or_else(|| {
                // outside protected region
                if let Some(last_segment) = self.segments.get_last_segment() {
                    let mut last_segment = last_segment.lock();

                    if let Some(ongoing_syscall) = last_segment.ongoing_syscall.take() {
                        assert_eq!(pid, self.main.pid);
                        assert_eq!(ongoing_syscall.exit_action, SyscallExitAction::Checkpoint);
                        drop(last_segment);

                        // restore registers as if we haven't modified any flags
                        self.main.modify_registers_with(|regs| {
                            regs.with_syscall_args(ongoing_syscall.syscall.into_parts().1)
                        });

                        self.handle_checkpoint(pid, false, false, CheckpointCaller::Shell);
                        skip_ptrace_syscall = true;
                    }
                }
            });

        if !skip_ptrace_syscall {
            ptrace::syscall(pid, None).unwrap();
        }
    }

    pub fn handle_signal(&self, pid: Pid, sig: Signal) {
        info!("[PID {: >8}] Signal: {:}", pid, sig);

        let mut suppress_signal = false;

        if sig == Signal::SIGSEGV {
            let process = Process::new(pid);
            let regs = process.read_registers();
            let instr: u64 = process
                .read_value(Addr::from_raw(regs.inner.rip as _).unwrap())
                .unwrap();

            if instr & 0xffff == 0x310f {
                info!("[PID {: >8}] Trap: Rdtsc", pid);

                // rdtsc
                let tsc = self
                    .segments
                    .get_active_segment_with(pid, |segment, is_main| {
                        if is_main {
                            let tsc = unsafe { _rdtsc() };
                            // add to the log
                            segment.trap_event_log.push_back(SavedTrapEvent::Rdtsc(tsc));
                            tsc
                        } else {
                            // replay from the log
                            let event = segment.trap_event_log.pop_front().unwrap();
                            if let SavedTrapEvent::Rdtsc(tsc) = event {
                                tsc
                            } else {
                                panic!("Unexpected trap event");
                            }
                        }
                    })
                    .unwrap_or_else(|| unsafe { _rdtsc() });

                process.write_registers(regs.with_tsc(tsc).with_offsetted_rip(2));

                suppress_signal = true;
            } else if instr & 0xffffff == 0xf9010f {
                info!("[PID {: >8}] Trap: Rdtscp", pid);

                // rdtscp
                let (tsc, aux) = self
                    .segments
                    .get_active_segment_with(pid, |segment, is_main| {
                        if is_main {
                            let mut aux = MaybeUninit::uninit();
                            // add to the log
                            let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
                            let aux = unsafe { aux.assume_init() };

                            segment
                                .trap_event_log
                                .push_back(SavedTrapEvent::Rdtscp(tsc, aux));

                            (tsc, aux)
                        } else {
                            // replay from the log
                            let event = segment.trap_event_log.pop_front().unwrap();
                            if let SavedTrapEvent::Rdtscp(tsc, aux) = event {
                                (tsc, aux)
                            } else {
                                panic!("Unexpected trap event");
                            }
                        }
                    })
                    .unwrap_or_else(|| {
                        let mut aux = MaybeUninit::uninit();
                        let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
                        let aux = unsafe { aux.assume_init() };
                        (tsc, aux)
                    });

                process.write_registers(regs.with_tscp(tsc, aux).with_offsetted_rip(3));

                suppress_signal = true;
            } else if instr & 0xffff == 0xa20f {
                info!("[PID {: >8}] Trap: Cpuid", pid);

                // cpuid
                let cpuid = self
                    .segments
                    .get_active_segment_with(pid, |segment, is_main| {
                        if is_main {
                            let (leaf, subleaf) = regs.cpuid_leaf_subleaf();
                            let cpuid = unsafe { __cpuid_count(leaf, subleaf) };
                            // add to the log
                            segment
                                .trap_event_log
                                .push_back(SavedTrapEvent::Cpuid(leaf, subleaf, cpuid));

                            cpuid
                        } else {
                            // replay from the log
                            let event = segment.trap_event_log.pop_front().unwrap();
                            if let SavedTrapEvent::Cpuid(leaf, subleaf, cpuid) = event {
                                assert_eq!(regs.cpuid_leaf_subleaf(), (leaf, subleaf));
                                cpuid
                            } else {
                                panic!("Unexpected trap event");
                            }
                        }
                    })
                    .unwrap_or_else(|| unsafe {
                        let (leaf, subleaf) = regs.cpuid_leaf_subleaf();
                        __cpuid_count(leaf, subleaf)
                    });

                process.write_registers(regs.with_cpuid_result(cpuid).with_offsetted_rip(2));

                suppress_signal = true;
            }
        }
        ptrace::syscall(pid, if suppress_signal { None } else { Some(sig) }).unwrap();
    }
}
