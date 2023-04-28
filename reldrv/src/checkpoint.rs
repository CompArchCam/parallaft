use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;

use bitflags::bitflags;

use log::{info, warn};
use nix::sys::ptrace;
use nix::sys::uio::RemoteIoVec;
use nix::sys::wait::{waitpid, WaitStatus};
use nix::{sched::CloneFlags, unistd::Pid};

use parking_lot::{Mutex, RwLock};

use reverie_syscalls::{
    Addr, AddrMut, Displayable, MapFlags, Syscall, SyscallArgs, SyscallInfo, Sysno,
};
use tokio::task;

use crate::client_control;
use crate::process::Process;
use crate::remote_memory::RemoteMemory;
use crate::saved_syscall::{
    SavedIncompleteSyscall, SavedIncompleteSyscallKind, SavedMemory, SavedSyscallKind,
    SyscallExitAction,
};
use crate::segments::{Checkpoint, SegmentChain};
use reverie_syscalls::may_rw::{SyscallMayRead, SyscallMayWrite};

pub struct CheckCoordinator<'c> {
    pub segments: Arc<SegmentChain>,
    pub main: Arc<Process>,
    pub epoch: AtomicU32,
    flags: CheckCoordinatorFlags,
    checker_cpu_affinity: &'c Vec<usize>,
    pending_sync: Arc<Mutex<Option<u32>>>,
    avg_nr_dirty_pages: Arc<Mutex<f64>>,
    client_control_addr: Arc<RwLock<Option<usize>>>,
}

bitflags! {
    pub struct CheckCoordinatorFlags: u32 {
        const SYNC_MEM_CHECK = 0b00000001;
        const NO_MEM_CHECK = 0b00000010;
        const DONT_RUN_CHECKER = 0b00000100;
        const DONT_CLEAR_SOFT_DIRTY = 0b00001000;

        #[cfg(feature = "compel")]
        const USE_LIBCOMPEL = 0b00010000;
        const DONT_FORK = 0b00100000;
    }
}

#[allow(unused)]
impl<'c> CheckCoordinator<'c> {
    pub fn new(
        main: Process,
        checker_cpu_affinity: &'c Vec<usize>,
        flags: CheckCoordinatorFlags,
    ) -> Self {
        let main_pid = main.pid;
        Self {
            main: Arc::new(main),
            segments: Arc::new(SegmentChain::new(main_pid)),
            epoch: AtomicU32::new(0),
            checker_cpu_affinity,
            flags,
            pending_sync: Arc::new(Mutex::new(None)),
            avg_nr_dirty_pages: Arc::new(Mutex::new(0.0)),
            client_control_addr: Arc::new(RwLock::new(None)),
        }
    }

    /// Handle checkpoint request from the target
    pub fn handle_checkpoint(&self, pid: Pid, is_finishing: bool) {
        if pid == self.main.pid {
            let epoch_local = self.epoch.fetch_add(1, Ordering::SeqCst);

            if self.flags.contains(CheckCoordinatorFlags::DONT_FORK) {
                self.main.resume();
                return;
            }

            let clone_flags = CloneFlags::CLONE_PARENT | CloneFlags::CLONE_PTRACE;
            let clone_signal = None;

            #[cfg(feature = "compel")]
            let use_libcompel = self.flags.contains(CheckCoordinatorFlags::USE_LIBCOMPEL);

            #[cfg(not(feature = "compel"))]
            let use_libcompel = false;

            if !is_finishing {
                let reference = self
                    .main
                    .clone_process(clone_flags, clone_signal, use_libcompel);

                if !self
                    .flags
                    .contains(CheckCoordinatorFlags::DONT_CLEAR_SOFT_DIRTY)
                {
                    self.main.clear_dirty_page_bits();
                }
                self.main.resume();

                let (checker, checkpoint) = match self.segments.is_last_checkpoint_finalizing() {
                    true => (reference, Checkpoint::new_initial(epoch_local)),
                    false => (
                        reference.clone_process(clone_flags, clone_signal, use_libcompel),
                        Checkpoint::new(epoch_local, reference),
                    ),
                };

                checker.set_cpu_affinity(&self.checker_cpu_affinity);
                if !self
                    .flags
                    .contains(CheckCoordinatorFlags::DONT_CLEAR_SOFT_DIRTY)
                {
                    checker.clear_dirty_page_bits();
                }

                info!("New checkpoint: {:?}", checkpoint);
                self.add_checkpoint(checkpoint, Some(checker));
            } else {
                if !self.segments.is_last_checkpoint_finalizing() {
                    let reference =
                        self.main
                            .clone_process(clone_flags, clone_signal, use_libcompel);
                    self.main.resume();
                    let checkpoint = Checkpoint::new(epoch_local, reference);

                    info!("New checkpoint: {:?}", checkpoint);
                    self.add_checkpoint(checkpoint, None);
                } else {
                    info!("No-op checkpoint_fini");
                    self.main.resume();
                }
            }
        } else if let Some(segment) = self.segments.get_segment_by_checker_pid(pid) {
            info!("Checker called checkpoint");

            if self.flags.contains(CheckCoordinatorFlags::NO_MEM_CHECK) {
                segment.lock().mark_as_checked().unwrap();
                Self::cleanup_committed_segments(
                    &self.main,
                    &mut self.pending_sync.lock(),
                    &self.segments,
                );
            } else if self.flags.contains(CheckCoordinatorFlags::SYNC_MEM_CHECK) {
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
                let avg_nr_dirty_pages = self.avg_nr_dirty_pages.clone();
                let client_control_addr = self.client_control_addr.clone();

                let main = self.main.clone();

                task::spawn_blocking(move || {
                    let mut segment = segment.lock();
                    let client_control_addr = client_control_addr.read();
                    let ignored_pages = client_control_addr
                        .as_ref()
                        .map_or(vec![], |a| vec![*a as u64]);

                    let (result, nr_dirty_pages) = segment.check(ignored_pages.as_slice()).unwrap();
                    let mut avg_nr_dirty_pages = avg_nr_dirty_pages.lock();

                    let alpha = 1.0 / (segment.nr + 1) as f64; // TODO: segments may finish out-of-order

                    *avg_nr_dirty_pages =
                        *avg_nr_dirty_pages * (1.0 - alpha) + (nr_dirty_pages as f64) * alpha;

                    drop(avg_nr_dirty_pages);
                    drop(segment);

                    if !result {
                        warn!("Check fails");
                    } else {
                        info!("Check passed");
                    }
                    Self::cleanup_committed_segments(&main, &mut pending_sync.lock(), &segments);
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
    ) {
        segments.cleanup_committed_segments();

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
    }

    /// Create a new checkpoint and kick off the checker of the previous checkpoint if needed.
    fn add_checkpoint(&self, checkpoint: Checkpoint, checker: Option<Process>) {
        self.segments.add_checkpoint(
            checkpoint,
            checker,
            |last_segment, checkpoint| {
                if self.flags.contains(CheckCoordinatorFlags::DONT_RUN_CHECKER) {
                    last_segment.mark_as_checked();
                    true
                } else {
                    let last_checker = last_segment.checker().unwrap();

                    // patch the checker's client_control struct
                    if let Some(base_address) = self.client_control_addr.read().as_ref() {
                        let this_reference = checkpoint.reference().unwrap();
                        let mut ctl =
                            client_control::read(this_reference.pid, *base_address).unwrap();
                        ctl.mode = client_control::CliMode::Checker;
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
        *self.avg_nr_dirty_pages.lock()
    }

    /// Check if all checkers has finished.
    pub fn is_all_finished(&self) -> bool {
        self.segments.is_empty()
    }

    pub fn set_client_control_addr(&self, base_address: usize) {
        self.client_control_addr.write().insert(base_address);
    }

    pub fn handle_syscall_entry(&self, pid: Pid, sysno: Sysno, args: SyscallArgs) {
        let syscall = reverie_syscalls::Syscall::from_raw(sysno, args);
        let memory = RemoteMemory::new(pid);

        info!("[PID {: >8}] Syscall: {:}", pid, syscall.display(&memory));

        if matches!(
            syscall,
            Syscall::Futex(_) | Syscall::Rseq(_) | Syscall::SetRobustList(_)
        ) {
            // rewrite unsupported syscalls
            info!("[PID {: >8}] Unsupported syscall", pid);
            let mut regs = ptrace::getregs(pid).unwrap();
            regs.orig_rax = 0xff77;
            regs.rax = 0xff77; // invalid syscall
            ptrace::setregs(pid, regs).unwrap();
            ptrace::syscall(pid, None).unwrap();
            assert!(matches!(
                waitpid(pid, None).unwrap(),
                WaitStatus::PtraceSyscall(pid)
            )); // TODO: don't block here
            ptrace::syscall(pid, None).unwrap();
            return;
        }

        if let Some((active_segment, is_main)) = self.segments.get_active_segment_by_pid(pid) {
            match syscall {
                Syscall::Execve(_) | Syscall::Execveat(_) => {
                    panic!("Execve(at) is disallowed in protected regions");
                }
                Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                    self.handle_checkpoint(pid, true);
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
                Syscall::Mmap(mmap) => {
                    let mut active_segment = active_segment.lock();

                    if is_main {
                        assert!(active_segment.ongoing_syscall.is_none());

                        let mmap = mmap.with_flags(
                            (mmap.flags() & !MapFlags::MAP_SHARED) | MapFlags::MAP_PRIVATE, // TODO: MAP_SHARED_VALIDATE
                        );

                        let (new_sysno, new_args) = mmap.into_parts();
                        self.main
                            .registers()
                            .with_sysno(new_sysno)
                            .with_syscall_args(new_args)
                            .write();

                        active_segment.ongoing_syscall = Some(SavedIncompleteSyscall {
                            syscall,
                            kind: SavedIncompleteSyscallKind::UnknownMemoryRw,
                            exit_action: SyscallExitAction::Custom,
                        });
                    } else {
                        // use MAP_FIXED, mapping exactly the same address that the main process did

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
                                .registers()
                                .with_sysno(new_sysno)
                                .with_syscall_args(new_args)
                                .write();
                        }
                    }
                }
                Syscall::Mremap(mremap) => {
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

                        if saved_syscall.ret_val != nix::libc::MAP_FAILED as _ {
                            // rewrite only if mmap has succeeded
                            let mremap = mremap
                                .with_new_addr(AddrMut::from_ptr(saved_syscall.ret_val as _))
                                .with_flags(mremap.flags() | nix::libc::MREMAP_FIXED as usize);

                            let (new_sysno, new_args) = mremap.into_parts();
                            active_segment
                                .checker()
                                .unwrap()
                                .registers()
                                .with_sysno(new_sysno)
                                .with_syscall_args(new_args)
                                .write();
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

                        let may_read = syscall.may_read(&memory).ok().map(|slices| {
                            slices
                                .iter()
                                .map(|slice| RemoteIoVec {
                                    base: unsafe { slice.as_ptr() as _ },
                                    len: slice.len(),
                                })
                                .collect::<Vec<RemoteIoVec>>()
                                .into_boxed_slice()
                        });

                        let may_write = syscall.may_write(&memory).ok().map(|slices| {
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
                                        mem_read: SavedMemory::save(&memory, &may_read).unwrap(),
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
                                    assert!(mem_read.compare(&memory).unwrap());
                                }
                            }
                        } else {
                            panic!("spurious syscall made by checker {:}", pid);
                        }

                        active_segment
                            .checker()
                            .unwrap()
                            .registers()
                            .with_syscall_skipped()
                            .write();
                    }
                }
            }
        };

        ptrace::syscall(pid, None).unwrap();
    }

    pub fn handle_syscall_exit(&self, pid: Pid, ret_val: isize) {
        let mut memory = RemoteMemory::new(pid);

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
                                } => SavedMemory::save(&memory, &mem_written_ranges).unwrap(),
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
                                        .registers()
                                        .with_syscall_args(args)
                                        .write();
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
                        SyscallExitAction::ReplicateMemoryWrites => match saved_syscall.kind {
                            SavedSyscallKind::KnownMemoryRw { mem_written, .. } => {
                                active_segment
                                    .checker()
                                    .unwrap()
                                    .registers()
                                    .with_syscall_ret_val(saved_syscall.ret_val)
                                    .write();
                                mem_written.dump(&mut memory).unwrap();
                            }
                            _ => panic!(),
                        },
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
                                        .registers()
                                        .with_syscall_args(args)
                                        .write();
                                }
                                _ => panic!("unhandled custom syscall during syscall exit"),
                            }
                        }
                    }
                }
            });

        ptrace::syscall(pid, None).unwrap();
    }
}
