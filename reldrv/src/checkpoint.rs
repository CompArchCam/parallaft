use std::collections::LinkedList;
use std::ops::DerefMut;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::{mem, ptr};

use bitflags::bitflags;

use log::{info, warn};
use nix::{sched::CloneFlags, unistd::Pid};

use parking_lot::{Mutex, RwLock};

use tokio::task;

use crate::client_control;
use crate::process::Process;

#[derive(Debug)]
pub enum CheckpointError {
    InvalidState,
}

type Result<T> = std::result::Result<T, CheckpointError>;

#[derive(Debug)]
pub enum CheckpointKind {
    Subsequent { reference: Process },
    Initial,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub kind: CheckpointKind,
    pub epoch: u32,
}

impl Checkpoint {
    pub fn new(epoch: u32, reference: Process) -> Self {
        Self {
            epoch,
            kind: CheckpointKind::Subsequent { reference },
        }
    }

    pub fn new_initial(epoch: u32) -> Self {
        Self {
            epoch,
            kind: CheckpointKind::Initial,
        }
    }

    pub fn reference<'a>(&'a self) -> Option<&'a Process> {
        match &self.kind {
            CheckpointKind::Subsequent { reference: ref_pid } => Some(ref_pid),
            CheckpointKind::Initial => None,
        }
    }
}

#[derive(Debug)]
pub enum SegmentStatus {
    New {
        checker: Process,
    },
    ReadyToCheck {
        checker: Process,
        checkpoint_end: Arc<Checkpoint>,
    },
    Checked {
        checkpoint_end: Arc<Checkpoint>,
    },
}

impl SegmentStatus {
    pub fn mark_as_ready(&mut self, checkpoint_end: Arc<Checkpoint>) -> Result<()> {
        let status = unsafe { ptr::read(self) };

        match status {
            SegmentStatus::New { checker } => {
                let new_status = SegmentStatus::ReadyToCheck {
                    checker,
                    checkpoint_end,
                };
                unsafe { ptr::write(self, new_status) };
                Ok(())
            }
            _ => {
                mem::forget(status);
                Err(CheckpointError::InvalidState)
            }
        }
    }

    pub fn mark_as_checked(&mut self) -> Result<()> {
        let status = unsafe { ptr::read(self) };

        match status {
            SegmentStatus::ReadyToCheck { checkpoint_end, .. } => {
                let new_status = SegmentStatus::Checked { checkpoint_end };
                unsafe { ptr::write(self, new_status) };
                Ok(())
            }
            _ => {
                mem::forget(status);
                Err(CheckpointError::InvalidState)
            }
        }
    }

    pub fn checkpoint_end<'a>(&'a self) -> Option<&'a Arc<Checkpoint>> {
        match self {
            SegmentStatus::ReadyToCheck { checkpoint_end, .. } => Some(checkpoint_end),
            SegmentStatus::Checked { checkpoint_end } => Some(checkpoint_end),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Segment {
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: SegmentStatus,
    pub nr: u32,
}

impl Segment {
    pub fn new(checkpoint_start: Arc<Checkpoint>, checker: Process, nr: u32) -> Self {
        Self {
            checkpoint_start,
            status: SegmentStatus::New { checker },
            nr,
        }
    }

    /// Mark this segment as "ready to check".
    /// This should happen when the main process reaches the ending checkpoint of this segment, i.e. the checkpoint immediately after the starting checkpoint.
    pub fn mark_as_ready(&mut self, checkpoint_end: Arc<Checkpoint>) -> Result<()> {
        assert!(matches!(
            checkpoint_end.kind,
            CheckpointKind::Subsequent { .. }
        ));
        self.status.mark_as_ready(checkpoint_end)
    }

    /// Compare dirty memory of the checker process and the reference process and mark the segment status as checked.
    /// This should be called after the checker process invokes the checkpoint syscall.
    pub fn check(&mut self, ignored_pages: &[u64]) -> Result<(bool, usize)> {
        if let SegmentStatus::ReadyToCheck {
            checker,
            checkpoint_end,
        } = &self.status
        {
            let (result, nr_dirty_pages) = checker
                .dirty_page_delta_against(checkpoint_end.reference().unwrap(), ignored_pages);
            self.mark_as_checked()?;

            Ok((result, nr_dirty_pages))
        } else {
            Err(CheckpointError::InvalidState)
        }
    }

    /// Mark this segment as "checked" without comparing dirty memory.
    pub fn mark_as_checked(&mut self) -> Result<()> {
        self.status.mark_as_checked()
    }

    /// Get the checker process, if it exists.
    pub fn checker<'a>(&'a self) -> Option<&'a Process> {
        match &self.status {
            SegmentStatus::New { checker } => Some(checker),
            SegmentStatus::ReadyToCheck { checker, .. } => Some(checker),
            _ => None,
        }
    }
}

pub struct CheckCoordinator<'c> {
    pub segments: Arc<RwLock<LinkedList<Arc<Mutex<Segment>>>>>,
    pub main: Arc<Process>,
    pub epoch: AtomicU32,
    flags: CheckCoordinatorFlags,
    checker_cpu_affinity: &'c Vec<usize>,
    pending_sync: Arc<Mutex<Option<u32>>>,
    avg_nr_dirty_pages: Arc<Mutex<f64>>,
    nr_segments: AtomicU32,
    client_control_addr: Arc<RwLock<Option<usize>>>,
}

bitflags! {
    pub struct CheckCoordinatorFlags: u32 {
        const SYNC_MEM_CHECK = 0b00000001;
        const NO_MEM_CHECK = 0b00000010;
        const DONT_RUN_CHECKER = 0b00000100;
        const DONT_CLEAR_SOFT_DIRTY = 0b00001000;
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
        Self {
            main: Arc::new(main),
            segments: Arc::new(RwLock::new(LinkedList::new())),
            epoch: AtomicU32::new(0),
            checker_cpu_affinity,
            flags,
            pending_sync: Arc::new(Mutex::new(None)),
            avg_nr_dirty_pages: Arc::new(Mutex::new(0.0)),
            nr_segments: AtomicU32::new(0),
            client_control_addr: Arc::new(RwLock::new(None)),
        }
    }

    /// Lookup not-checked segment by its checker PID
    pub fn lookup_segment_by_checker_pid_mut<'a>(&self, pid: Pid) -> Option<Arc<Mutex<Segment>>> {
        self.segments
            .read()
            .iter()
            .find(|s| s.lock().checker().map_or(false, |c| c.pid == pid))
            .map(|t| t.clone())
    }

    #[cfg(feature = "track_zombie_children")]
    pub fn handle_sigchld(&self, to_pid: Pid, from_pid: Pid) -> bool {
        if to_pid == self.main.pid && self.main.zombie_children.lock().contains(&from_pid) {
            self.main.reap_zombie_child(from_pid);
            true
        } else {
            false
        }
    }

    fn is_last_checkpoint_finishing(&self) -> bool {
        let segments = self.segments.read();

        match segments.back() {
            Some(segment) => match segment.lock().status {
                SegmentStatus::New { .. } => false,
                _ => true,
            },
            None => true,
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
            let use_libcompel = self.flags.contains(CheckCoordinatorFlags::USE_LIBCOMPEL);

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

                let (checker, checkpoint) = match self.is_last_checkpoint_finishing() {
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
                if !self.is_last_checkpoint_finishing() {
                    let reference =
                        self.main
                            .clone_process(clone_flags, clone_signal, use_libcompel);
                    self.main.resume();
                    let checkpoint = Checkpoint::new(epoch_local, reference);

                    info!("New checkpoint: {:?}", checkpoint);
                    self.add_checkpoint(checkpoint, None);
                }
            }
        } else if let Some(segment) = self.lookup_segment_by_checker_pid_mut(pid) {
            info!("Checker called checkpoint");

            if self.flags.contains(CheckCoordinatorFlags::NO_MEM_CHECK) {
                segment.lock().mark_as_checked().unwrap();
                Self::cleanup_committed_segments(
                    &self.main,
                    self.pending_sync.lock().deref_mut(),
                    self.segments.write().deref_mut(),
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
                    Self::cleanup_committed_segments(
                        &main,
                        pending_sync.lock().deref_mut(),
                        segments.write().deref_mut(),
                    );
                });
            }
        } else {
            panic!("invalid pid");
        }
    }

    pub fn handle_sync(&self) {
        let segments = self.segments.read();

        if let Some(last_segment) = segments.back() {
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
        segments: &mut LinkedList<Arc<Mutex<Segment>>>,
    ) {
        loop {
            let mut should_break = true;
            let front = segments.front();
            if let Some(front) = front {
                let front = front.lock();
                if let SegmentStatus::Checked { .. } = front.status {
                    mem::drop(front);
                    segments.pop_front();
                    should_break = false;
                }
            }
            if should_break {
                break;
            }
        }

        if let Some(epoch) = pending_sync.as_ref() {
            if let Some(front) = segments.front() {
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
        let checkpoint = Arc::new(checkpoint);
        let mut do_cleanup = false;

        if !self.is_last_checkpoint_finishing() {
            if let Some(last_segment) = self.segments.read().back() {
                let mut last_segment = last_segment.lock();
                last_segment.mark_as_ready(checkpoint.clone()).unwrap();

                if self.flags.contains(CheckCoordinatorFlags::DONT_RUN_CHECKER) {
                    last_segment.mark_as_checked();
                    do_cleanup = true;
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
                }
            }
        }

        let mut segments = self.segments.write();

        if let Some(checker) = checker {
            let segment = Segment::new(
                checkpoint,
                checker,
                self.nr_segments.fetch_add(1, Ordering::SeqCst),
            );
            info!("New segment: {:?}", segment);
            segments.push_back(Arc::new(Mutex::new(segment)));
        }

        if do_cleanup {
            Self::cleanup_committed_segments(
                &self.main,
                self.pending_sync.lock().deref_mut(),
                segments.deref_mut(),
            );
        }
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
        self.segments.read().is_empty()
    }

    pub fn set_client_control_addr(&self, base_address: usize) {
        self.client_control_addr.write().insert(base_address);
    }
}
