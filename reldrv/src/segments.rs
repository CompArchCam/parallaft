use std::arch::x86_64::CpuidResult;
use std::collections::LinkedList;
use std::fmt::Debug;
use std::ops::{Deref, DerefMut};
use std::sync::atomic::{AtomicU32, Ordering};
use std::sync::Arc;
use std::{mem, ptr};

use log::info;
use nix::unistd::Pid;
use parking_lot::{Mutex, RwLock};

use crate::error::{Error, Result};
use crate::process::{OwnedProcess, Process};
use crate::saved_syscall::{SavedIncompleteSyscall, SavedSyscall};

#[derive(Debug)]
pub enum CheckpointKind {
    Subsequent {
        reference: OwnedProcess,
        nr_dirty_pages: usize,
    },
    Initial,
}

// Who made the checkpoint request
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CheckpointCaller {
    Child,
    Shell,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub kind: CheckpointKind,
    pub caller: CheckpointCaller,
    pub epoch: u32,
}

impl Checkpoint {
    pub fn new(
        epoch: u32,
        reference: OwnedProcess,
        nr_dirty_pages: usize,
        caller: CheckpointCaller,
    ) -> Self {
        Self {
            epoch,
            caller,
            kind: CheckpointKind::Subsequent {
                reference,
                nr_dirty_pages,
            },
        }
    }

    pub fn new_initial(epoch: u32, caller: CheckpointCaller) -> Self {
        Self {
            epoch,
            caller,
            kind: CheckpointKind::Initial,
        }
    }

    pub fn reference<'a>(&'a self) -> Option<&'a OwnedProcess> {
        match &self.kind {
            CheckpointKind::Subsequent {
                reference: ref_pid, ..
            } => Some(ref_pid),
            CheckpointKind::Initial => None,
        }
    }

    pub fn nr_dirty_pages(&self) -> usize {
        match &self.kind {
            CheckpointKind::Subsequent { nr_dirty_pages, .. } => *nr_dirty_pages,
            CheckpointKind::Initial => 0,
        }
    }
}

#[derive(Debug)]
pub enum SegmentStatus {
    New {
        checker: OwnedProcess,
    },
    ReadyToCheck {
        checker: OwnedProcess,
        checkpoint_end: Arc<Checkpoint>,
    },
    Checked {
        checkpoint_end: Arc<Checkpoint>,
        has_errors: bool,
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
                Err(Error::InvalidState)
            }
        }
    }

    pub fn mark_as_checked(&mut self, has_errors: bool) -> Result<()> {
        let status = unsafe { ptr::read(self) };

        match status {
            SegmentStatus::ReadyToCheck { checkpoint_end, .. } => {
                let new_status = SegmentStatus::Checked {
                    checkpoint_end,
                    has_errors,
                };
                unsafe { ptr::write(self, new_status) };
                Ok(())
            }
            _ => {
                mem::forget(status);
                Err(Error::InvalidState)
            }
        }
    }

    pub fn checkpoint_end<'a>(&'a self) -> Option<&'a Arc<Checkpoint>> {
        match self {
            SegmentStatus::ReadyToCheck { checkpoint_end, .. } => Some(checkpoint_end),
            SegmentStatus::Checked { checkpoint_end, .. } => Some(checkpoint_end),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub enum SavedTrapEvent {
    Rdtsc(u64),
    Rdtscp(u64, u32),             // tsc, aux
    Cpuid(u32, u32, CpuidResult), // leaf, subleaf, result
}

#[derive(Debug)]
pub struct Segment {
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: SegmentStatus,
    pub nr: u32,
    pub syscall_log: LinkedList<SavedSyscall>,
    pub ongoing_syscall: Option<SavedIncompleteSyscall>,
    pub trap_event_log: LinkedList<SavedTrapEvent>,
}

#[allow(unused)]
impl Segment {
    pub fn new(checkpoint_start: Arc<Checkpoint>, checker: OwnedProcess, nr: u32) -> Self {
        Self {
            checkpoint_start,
            status: SegmentStatus::New { checker },
            nr,
            syscall_log: LinkedList::new(),
            ongoing_syscall: None,
            trap_event_log: LinkedList::new(),
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
    pub fn check(&mut self, ignored_pages: &[usize]) -> Result<(bool, usize)> {
        if let SegmentStatus::ReadyToCheck {
            checker,
            checkpoint_end,
        } = &self.status
        {
            let (result, nr_dirty_pages) = checker
                .dirty_page_delta_against(checkpoint_end.reference().unwrap(), ignored_pages)?;
            self.mark_as_checked(!result).unwrap();

            Ok((result, nr_dirty_pages))
        } else {
            Err(Error::InvalidState)
        }
    }

    /// Mark this segment as "checked" without comparing dirty memory.
    pub fn mark_as_checked(&mut self, has_errors: bool) -> Result<()> {
        self.status.mark_as_checked(has_errors)
    }

    /// Get the checker process, if it exists.
    pub fn checker<'a>(&'a self) -> Option<&'a Process> {
        match &self.status {
            SegmentStatus::New { checker } => Some(checker),
            SegmentStatus::ReadyToCheck { checker, .. } => Some(checker),
            _ => None,
        }
    }

    /// Get the reference process, it it exists.
    pub fn reference<'a>(&'a self) -> Option<&'a Process> {
        self.checkpoint_start.reference().map(|r| r.deref())
    }

    pub fn nr_dirty_pages(&self) -> Option<usize> {
        self.status.checkpoint_end().map(|c| c.nr_dirty_pages())
    }

    pub fn has_errors(&self) -> bool {
        match self.status {
            SegmentStatus::Checked { has_errors, .. } => has_errors,
            _ => false,
        }
    }
}

type SegmentList = RwLock<LinkedList<Arc<Mutex<Segment>>>>;

#[derive(Debug)]
pub struct SegmentChain {
    main_pid: Pid,
    pub inner: SegmentList,
    nr_segments: AtomicU32,
}

#[allow(unused)]
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
            return None;
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

    /// Clean up committed segments. Returns a tuple indicating if any segment has errors
    /// unless `ignore_errors` is set, as well as the number of active segments after the cleanup.
    /// Erroneous segments will not be cleaned up unless `ignore_errors` is set.
    pub fn cleanup_committed_segments(&self, ignore_errors: bool) -> (bool, usize) {
        let mut segments = self.inner.write();
        loop {
            let mut should_break = true;
            let front = segments.front();
            if let Some(front) = front {
                let front = front.lock();
                if let SegmentStatus::Checked { has_errors, .. } = front.status {
                    if !ignore_errors && has_errors {
                        return (true, segments.len());
                    }
                    mem::drop(front);
                    segments.pop_front();
                    should_break = false;
                }
            }
            if should_break {
                break;
            }
        }

        (false, segments.len())
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
        checker: Option<OwnedProcess>,
        on_segment_ready: impl FnOnce(&mut Segment, &Checkpoint) -> Result<bool>,
        on_segment_created: impl FnOnce(&Segment) -> Result<()>,
        on_segment_chain_closed: impl FnOnce(&Segment) -> Result<()>,
        on_cleanup_needed: impl FnOnce() -> Result<()>,
    ) -> Result<()> {
        let checkpoint = Arc::new(checkpoint);
        let mut do_cleanup = false;

        if !self.is_last_checkpoint_finalizing() {
            if let Some(last_segment) = self.inner.read().back() {
                let mut last_segment = last_segment.lock();
                last_segment.mark_as_ready(checkpoint.clone())?;

                do_cleanup = on_segment_ready(&mut last_segment, &checkpoint)?;
            }
        }

        if let Some(checker) = checker {
            let segment = Segment::new(
                checkpoint,
                checker,
                self.nr_segments.fetch_add(1, Ordering::SeqCst),
            );
            info!("New segment: {:?}", segment);
            on_segment_created(&segment)?;

            self.inner.write().push_back(Arc::new(Mutex::new(segment)));
        } else {
            if let Some(last_segment) = self.inner.read().back() {
                let last_segment = last_segment.lock();
                on_segment_chain_closed(&last_segment)?;
            } else {
                return Err(Error::InvalidState);
            }
        }

        if do_cleanup {
            on_cleanup_needed()?;
        }

        Ok(())
    }

    pub fn is_empty(&self) -> bool {
        self.inner.read().is_empty()
    }

    pub fn has_errors(&self) -> bool {
        self.inner
            .read()
            .iter()
            .any(|segment| segment.lock().has_errors())
    }

    pub fn len(&self) -> usize {
        self.inner.read().len()
    }

    pub fn nr_live_segments(&self) -> usize {
        self.inner
            .read()
            .iter()
            .filter(|s| {
                matches!(
                    s.lock().status,
                    SegmentStatus::Checked { .. } | SegmentStatus::ReadyToCheck { .. }
                )
            })
            .count()
    }

    /// Get the total number of dirty pages in this segment chain.
    pub fn nr_dirty_pages(&self) -> usize {
        self.inner
            .read()
            .iter()
            .map(|segment| {
                let segment = segment.lock();
                segment.nr_dirty_pages().unwrap_or(0)
            })
            .sum()
    }
}

#[allow(unused)]
pub trait SegmentEventHandler {
    fn handle_segment_created(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_chain_closed(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_ready(
        &self,
        segment: &mut Segment,
        checkpoint_end_caller: CheckpointCaller,
    ) -> Result<()> {
        Ok(())
    }
}
