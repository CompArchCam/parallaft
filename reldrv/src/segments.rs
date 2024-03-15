#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

use std::collections::LinkedList;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Deref, Range};
use std::sync::Arc;
use std::{mem, ptr};

use log::{debug, error, info};
use nix::unistd::Pid;
use parking_lot::lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard};
use parking_lot::{Mutex, MutexGuard, RawRwLock, RwLock};

use crate::check_coord::ProcessRole;
use crate::dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressTrackerContext};
use crate::error::{Error, Result};
use crate::process::detach::DetachedProcess;
use crate::process::dirty_pages::{filter_writable_addresses, merge_page_addresses, page_diff};
use crate::process::{OwnedProcess, Process};
use crate::saved_syscall::{SavedIncompleteSyscall, SavedSyscall};

pub type EpochId = u32;
pub type SegmentId = u32;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckFailReason {
    MemoryMapMismatch,
    MemoryMismatch,
    RegisterMismatch,
}

#[derive(Debug)]
pub enum CheckpointKind {
    Subsequent {
        reference: Mutex<DetachedProcess<OwnedProcess>>,
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
    pub epoch: EpochId,
}

impl Checkpoint {
    pub fn subsequent(epoch: EpochId, reference: OwnedProcess, caller: CheckpointCaller) -> Self {
        Self {
            epoch,
            caller,
            kind: CheckpointKind::Subsequent {
                reference: Mutex::new(
                    DetachedProcess::detach_from(reference).expect("Failed to detach process"),
                ),
            },
        }
    }

    pub fn initial(epoch: EpochId, caller: CheckpointCaller) -> Self {
        Self {
            epoch,
            caller,
            kind: CheckpointKind::Initial,
        }
    }

    pub fn reference<'a>(&'a self) -> Option<MutexGuard<'a, DetachedProcess<OwnedProcess>>> {
        match &self.kind {
            CheckpointKind::Subsequent { reference, .. } => Some(reference.lock()),
            CheckpointKind::Initial => None,
        }
    }
}

#[derive(Debug)]
pub enum SegmentStatus {
    // TODO: Uninitialized,
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
    /// Main process does not complete the segment
    Incomplete,
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
    #[cfg(target_arch = "x86_64")]
    Rdtsc(u64),

    #[cfg(target_arch = "x86_64")]
    Rdtscp(u64, u32), // tsc, aux

    #[cfg(target_arch = "x86_64")]
    Cpuid(u32, u32, CpuidResult), // leaf, subleaf, result
}

#[derive(Debug)]
pub struct SegmentReplay {
    pub ongoing_syscall: Option<SavedIncompleteSyscall>,
    pub syscall_log: LinkedList<SavedSyscall>, // TODO: use vec
    pub trap_event_log: LinkedList<SavedTrapEvent>, // TODO: use vec
}

#[derive(Debug)]
pub struct Segment {
    pub nr: SegmentId,
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: SegmentStatus,
    pub replay: SegmentReplay,
    pub dirty_page_addresses_main: Vec<usize>,
    pub dirty_page_addresses_checker: Vec<usize>,
}

impl Hash for Segment {
    fn hash<H: std::hash::Hasher>(&self, state: &mut H) {
        self.nr.hash(state);
    }
}

impl PartialEq for Segment {
    fn eq(&self, other: &Self) -> bool {
        self.nr == other.nr
    }
}

impl Eq for Segment {}

impl PartialOrd for Segment {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        self.nr.partial_cmp(&other.nr)
    }
}

impl Ord for Segment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.nr.cmp(&other.nr)
    }
}

impl Segment {
    pub fn new(checkpoint_start: Arc<Checkpoint>, checker: OwnedProcess, nr: u32) -> Self {
        Self {
            nr,
            checkpoint_start,
            status: SegmentStatus::New { checker },
            replay: SegmentReplay {
                syscall_log: LinkedList::new(),
                ongoing_syscall: None,
                trap_event_log: LinkedList::new(),
            },
            dirty_page_addresses_main: Vec::new(),
            dirty_page_addresses_checker: Vec::new(),
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

    /// Compare dirty memory of the checker process and the reference process without marking the segment status as checked.
    /// This should be called after the checker process invokes the checkpoint syscall.
    pub fn check(
        &mut self,
        main_pid: Pid,
        ignored_pages: &[usize],
        extra_writable_ranges: &[Range<usize>],
        dirty_page_tracker: &(dyn DirtyPageAddressTracker + Sync),
    ) -> Result<(std::result::Result<(), CheckFailReason>, usize)> {
        if let SegmentStatus::ReadyToCheck {
            checker,
            checkpoint_end,
        } = &self.status
        {
            let ctx = DirtyPageAddressTrackerContext {
                segment: self,
                main_pid,
            };

            let (dpa_main, dpa_main_flags) =
                dirty_page_tracker.take_dirty_pages_addresses(self.nr, ProcessRole::Main, &ctx)?;

            let dpa_main = dpa_main
                .as_ref()
                .as_ref()
                .into_iter()
                .map(|&x| x)
                .collect::<Vec<usize>>();

            let (dpa_checker, dpa_checker_flags) = dirty_page_tracker.take_dirty_pages_addresses(
                self.nr,
                ProcessRole::Checker,
                &ctx,
            )?;

            let dpa_checker = dpa_checker
                .as_ref()
                .as_ref()
                .into_iter()
                .map(|&x| x)
                .collect::<Vec<usize>>();

            self.dirty_page_addresses_main = dpa_main;
            self.dirty_page_addresses_checker = dpa_checker;

            let mut dpa_merged = merge_page_addresses(
                &self.dirty_page_addresses_checker,
                &self.dirty_page_addresses_main,
                ignored_pages,
            );
            let mut nr_dirty_pages = dpa_merged.len();

            let checker = checker.deref();
            let mut reference = checkpoint_end.reference().unwrap();

            info!("Comparing registers");

            let checker_regs = checker.read_registers_precise()?;
            let reference_registers = reference.borrow_with(|p2| p2.read_registers())??;

            if checker_regs != reference_registers {
                error!("Register differs for epoch {}", self.checkpoint_start.epoch);
                info!("Checker registers:\n{}", checker_regs.dump());
                info!("Reference registers:\n{}", reference_registers.dump());

                return Ok((Err(CheckFailReason::RegisterMismatch), nr_dirty_pages));
            }

            let checker_writable_ranges = checker.get_writable_ranges()?;
            let reference_writable_ranges = reference.get_writable_ranges()?;

            if checker_writable_ranges != reference_writable_ranges {
                error!(
                    "Memory map differs for epoch {}",
                    self.checkpoint_start.epoch
                );
                return Ok((Err(CheckFailReason::MemoryMapMismatch), nr_dirty_pages));
            }

            if !dpa_main_flags.contains_writable_only || !dpa_checker_flags.contains_writable_only {
                let writable_ranges = checker_writable_ranges
                    .into_iter()
                    .chain(extra_writable_ranges.into_iter())
                    .cloned()
                    .collect::<Vec<_>>();

                dpa_merged = filter_writable_addresses(dpa_merged, &writable_ranges);
                nr_dirty_pages = dpa_merged.len();
            }

            info!("Comparing {} dirty pages", nr_dirty_pages);

            if !reference.borrow_with(|reference_borrowed| {
                page_diff(checker, (*reference_borrowed).as_ref(), &dpa_merged)
            })?? {
                error!("Memory differs for epoch {}", self.checkpoint_start.epoch);
                return Ok((Err(CheckFailReason::MemoryMismatch), nr_dirty_pages));
            }

            Ok((Ok(()), nr_dirty_pages))
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

    /// Get the reference process at the start of the segment, it it exists.
    pub fn reference_start<'a>(&'a self) -> Option<MutexGuard<'a, DetachedProcess<OwnedProcess>>> {
        self.checkpoint_start.reference()
    }

    /// Get the reference process at the end of the segment, it it exists.
    pub fn reference_end<'a>(&'a self) -> Option<MutexGuard<'a, DetachedProcess<OwnedProcess>>> {
        self.status.checkpoint_end().and_then(|c| c.reference())
    }

    pub fn has_errors(&self) -> bool {
        match self.status {
            SegmentStatus::Checked { has_errors, .. } => has_errors,
            _ => false,
        }
    }

    pub fn is_checked(&self) -> bool {
        match self.status {
            SegmentStatus::Checked { .. } => true,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct SegmentChains {
    pub list: LinkedList<Arc<RwLock<Segment>>>,
    pub next_id: SegmentId,
    in_chain: bool,
}

impl SegmentChains {
    pub fn new() -> Self {
        Self {
            list: LinkedList::new(),
            next_id: 0,
            in_chain: false,
        }
    }

    /// Get the number of live segments in this segment chain.
    pub fn nr_live_segments(&self) -> usize {
        self.list
            .iter()
            .filter(|s| {
                matches!(
                    s.read_recursive().status,
                    SegmentStatus::Checked { .. } | SegmentStatus::ReadyToCheck { .. }
                )
            })
            .count()
    }

    /// Check if there are any checking errors in this segment chain.
    pub fn has_errors(&self) -> bool {
        self.list.iter().any(|segment| segment.read().has_errors())
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn last_segment(&self) -> Option<Arc<RwLock<Segment>>> {
        self.list.back().map(|s| s.clone())
    }

    pub fn first_segment(&self) -> Option<Arc<RwLock<Segment>>> {
        self.list.front().map(|s| s.clone())
    }

    // pub fn on_chain_head(&self) -> bool {
    //     match self.list.back() {
    //         Some(segment) => match segment.read_recursive().status {
    //             SegmentStatus::New { .. } => false,
    //             _ => true,
    //         },
    //         None => true,
    //     }
    // }

    pub fn in_chain(&self) -> bool {
        self.in_chain
    }

    pub fn add_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        checker: Option<OwnedProcess>,
        on_segment_ready: impl FnOnce(
            ArcRwLockWriteGuard<RawRwLock, Segment>,
            &Checkpoint,
        ) -> Result<bool>,
        on_segment_created: impl FnOnce(ArcRwLockReadGuard<RawRwLock, Segment>) -> Result<()>,
        on_segment_chain_closed: impl FnOnce(ArcRwLockReadGuard<RawRwLock, Segment>) -> Result<()>,
        on_cleanup_needed: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let checkpoint = Arc::new(checkpoint);
        let mut do_cleanup = false;

        if let Some(last_segment) = self.list.back() {
            let mut last_segment = last_segment.write_arc();

            if matches!(last_segment.status, SegmentStatus::New { .. }) {
                last_segment.mark_as_ready(checkpoint.clone())?;
                do_cleanup = on_segment_ready(last_segment, &checkpoint)?;
            }
        }

        if let Some(checker) = checker {
            let segment = Segment::new(checkpoint, checker, self.next_id);
            self.next_id += 1;
            self.in_chain = true;

            debug!("New segment: {:?}", segment);

            let segment_arc = Arc::new(RwLock::new(segment));
            let segment_mg = segment_arc.read_arc_recursive();
            self.list.push_back(segment_arc);
            on_segment_created(segment_mg)?;
        } else {
            if let Some(last_segment) = self.list.back() {
                self.in_chain = false;
                let last_segment = last_segment.read_arc_recursive();
                on_segment_chain_closed(last_segment)?;
            } else {
                return Err(Error::InvalidState);
            }
        }

        if do_cleanup {
            on_cleanup_needed(self)?;
        }

        Ok(())
    }

    /// Clean up committed segments. Returns a tuple indicating if any segment has errors
    /// unless `ignore_errors` is set, as well as the number of active segments after the cleanup.
    /// Erroneous segments will not be cleaned up unless `ignore_errors` is set.
    pub fn cleanup_committed_segments(
        &mut self,
        ignore_errors: bool,
        on_segment_removed: impl Fn(&Segment) -> Result<()>,
    ) -> Result<bool> {
        loop {
            let mut should_break = true;
            let front = self.list.front();
            if let Some(front) = front {
                let front = front.read();
                if let SegmentStatus::Checked { has_errors, .. } = front.status {
                    if !ignore_errors && has_errors {
                        return Ok(true);
                    }

                    on_segment_removed(&front)?;
                    mem::drop(front);
                    self.list.pop_front();
                    should_break = false;
                }
            }
            if should_break {
                break;
            }
        }

        Ok(false)
    }

    pub fn main_segment(&self) -> Option<Arc<RwLock<Segment>>> {
        if self.in_chain {
            self.list.back().map(|segment| segment.clone())
        } else {
            None
        }
    }

    /// Get the total number of dirty pages in this segment chain.
    pub fn nr_dirty_pages(&self) -> usize {
        self.list
            .iter()
            .map(|segment| {
                let segment = segment.read();
                segment.dirty_page_addresses_main.len()
            })
            .sum()
    }
}

#[allow(unused_variables)]
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

    fn handle_segment_checked(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_checkpoint_created_pre(
        &self,
        main_pid: Pid,
        last_segment_id: Option<SegmentId>,
    ) -> Result<()> {
        Ok(())
    }
}
