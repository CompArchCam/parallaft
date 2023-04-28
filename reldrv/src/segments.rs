use std::collections::LinkedList;
use std::ops::DerefMut;
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::{mem, ptr};

use log::info;
use nix::unistd::Pid;
use parking_lot::{Mutex, RwLock};

use crate::process::Process;
use crate::saved_syscall::{SavedIncompleteSyscall, SavedSyscall};

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
    pub syscall_log: LinkedList<SavedSyscall>,
    pub ongoing_syscall: Option<SavedIncompleteSyscall>,
}

impl Segment {
    pub fn new(checkpoint_start: Arc<Checkpoint>, checker: Process, nr: u32) -> Self {
        Self {
            checkpoint_start,
            status: SegmentStatus::New { checker },
            nr,
            syscall_log: LinkedList::new(),
            ongoing_syscall: None,
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

type SegmentList = RwLock<LinkedList<Arc<Mutex<Segment>>>>;

#[derive(Debug)]
pub struct SegmentChain {
    main_pid: Pid,
    inner: SegmentList,
    nr_segments: AtomicU32,
}

impl SegmentChain {
    pub fn new(main_pid: Pid) -> Self {
        Self {
            main_pid,
            inner: RwLock::new(LinkedList::new()),
            nr_segments: AtomicU32::new(0),
        }
    }

    pub fn get_last_segment(&self) -> Option<Arc<Mutex<Segment>>> {
        self.inner.read().back().map(|s| s.clone())
    }

    pub fn get_first_segment(&self) -> Option<Arc<Mutex<Segment>>> {
        self.inner.read().front().map(|s| s.clone())
    }

    pub fn get_segment_by_checker_pid(&self, pid: Pid) -> Option<Arc<Mutex<Segment>>> {
        self.inner
            .read()
            .iter()
            .find(|&s| s.lock().checker().map_or(false, |c| c.pid == pid))
            .map(|t| t.clone())
    }

    pub fn get_active_segment_by_pid(&self, pid: Pid) -> Option<(Arc<Mutex<Segment>>, bool)> {
        if pid == self.main_pid {
            if let Some(last_segment) = self.inner.read().back() {
                let last_segment_locked = last_segment.lock();
                if matches!(last_segment_locked.status, SegmentStatus::New { .. }) {
                    return Some((last_segment.clone(), true));
                }
            }
        } else if let Some(segment) = self.get_segment_by_checker_pid(pid) {
            return Some((segment, false));
        } else {
            panic!("unexpected pid")
        }

        None
    }

    pub fn is_last_checkpoint_finalizing(&self) -> bool {
        let segments = self.inner.read();

        match segments.back() {
            Some(segment) => match segment.lock().status {
                SegmentStatus::New { .. } => false,
                _ => true,
            },
            None => true,
        }
    }

    pub fn cleanup_committed_segments(&self) {
        let mut segments = self.inner.write();
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
    }

    pub fn get_active_segment_with<R>(
        &self,
        pid: Pid,
        f: impl FnOnce(&mut Segment, bool) -> R,
    ) -> Option<R> {
        self.get_active_segment_by_pid(pid)
            .map(|(segment, is_main)| f(segment.lock().deref_mut(), is_main))
    }

    pub fn add_checkpoint(
        &self,
        checkpoint: Checkpoint,
        checker: Option<Process>,
        on_segment_ready: impl FnOnce(&mut Segment, &Checkpoint) -> bool,
        on_cleanup_needed: impl FnOnce() -> (),
    ) {
        let checkpoint = Arc::new(checkpoint);
        let mut do_cleanup = false;

        if !self.is_last_checkpoint_finalizing() {
            if let Some(last_segment) = self.inner.read().back() {
                let mut last_segment = last_segment.lock();
                last_segment.mark_as_ready(checkpoint.clone()).unwrap();

                do_cleanup = on_segment_ready(&mut last_segment, &checkpoint);
            }
        }

        if let Some(checker) = checker {
            let segment = Segment::new(
                checkpoint,
                checker,
                self.nr_segments.fetch_add(1, Ordering::SeqCst),
            );
            info!("New segment: {:?}", segment);
            self.inner.write().push_back(Arc::new(Mutex::new(segment)));
        }

        if do_cleanup {
            on_cleanup_needed();
        }
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }
}
