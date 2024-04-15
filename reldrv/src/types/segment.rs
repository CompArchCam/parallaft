use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Deref, Range};
use std::sync::Arc;

use log::{error, info};
use nix::unistd::Pid;
use parking_lot::MutexGuard;

use crate::check_coord::ProcessRole;
use crate::dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressTrackerContext};
use crate::error::{Error, Result};
use crate::events::comparator::{RegisterComparator, RegisterComparsionResult};
use crate::process::detach::DetachedProcess;
use crate::process::dirty_pages::{filter_writable_addresses, merge_page_addresses, page_diff};
use crate::process::OwnedProcess;

use super::checker::{CheckFailReason, Checker, CheckerStatus};
use super::checkpoint::Checkpoint;
use super::segment_record::SegmentRecord;

pub type SegmentId = u32;

#[derive(Debug)]
pub enum SegmentStatus {
    /// The main process is running on this segment.
    Filling,

    /// The main process finished this segment.
    Done(Arc<Checkpoint>),

    /// Something went wrong.
    Crashed,
}

impl SegmentStatus {
    pub fn mark_as_done(&mut self, checkpoint: Arc<Checkpoint>) {
        assert!(matches!(self, SegmentStatus::Filling));
        *self = SegmentStatus::Done(checkpoint);
    }

    pub fn checkpoint_end<'a>(&'a self) -> Option<&'a Arc<Checkpoint>> {
        match self {
            SegmentStatus::Done(ckpt) => Some(ckpt),
            _ => None,
        }
    }
}

#[derive(Debug)]
pub struct Segment {
    pub nr: SegmentId,
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: SegmentStatus,
    pub record: SegmentRecord,
    pub checker: Checker,
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
    pub fn new(checkpoint_start: Arc<Checkpoint>, nr: SegmentId) -> Self {
        Self {
            nr,
            checkpoint_start,
            status: SegmentStatus::Filling,
            record: SegmentRecord::new(),
            dirty_page_addresses_main: Vec::new(),
            dirty_page_addresses_checker: Vec::new(),
            checker: Checker::new(),
        }
    }

    /// Mark this segment as "ready to check".
    /// This should happen when the main process reaches the ending checkpoint of this segment, i.e. the checkpoint immediately after the starting checkpoint.
    pub fn mark_as_done(&mut self, checkpoint_end: Arc<Checkpoint>) {
        self.status.mark_as_done(checkpoint_end);
    }

    pub fn start_checker(&mut self) -> Result<&OwnedProcess> {
        match &self.status {
            SegmentStatus::Done(..) => {
                self.record.reset();
                let checker_process = self.checker.start(&self.checkpoint_start)?;
                Ok(checker_process)
            },
            _ => panic!("Attempting to start checking when the main process has not yet completed the segment"),
        }
    }

    /// Compare dirty memory of the checker process and the reference process without marking the segment status as checked.
    /// This should be called after the checker process invokes the checkpoint syscall.
    pub fn check(
        &mut self,
        main_pid: Pid,
        ignored_pages: &[usize],
        extra_writable_ranges: &[Range<usize>],
        dirty_page_tracker: &(dyn DirtyPageAddressTracker + Sync),
        comparator: &impl RegisterComparator,
    ) -> Result<(std::result::Result<(), CheckFailReason>, usize)> {
        let checkpoint_end = if let SegmentStatus::Done(checkpoint_end) = &self.status {
            checkpoint_end
        } else {
            panic!("Invalid segment status")
        };

        let checker_process = if let CheckerStatus::Checking(checker_process) = &self.checker.status
        {
            checker_process.deref()
        } else {
            panic!("Invalid checker status")
        };

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

        let (dpa_checker, dpa_checker_flags) =
            dirty_page_tracker.take_dirty_pages_addresses(self.nr, ProcessRole::Checker, &ctx)?;

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

        let mut reference = checkpoint_end.process.lock();

        info!("Comparing registers");

        let mut checker_regs = checker_process.read_registers_precise()?.strip_orig();
        let mut reference_registers = reference
            .borrow_with(|p2| p2.read_registers())??
            .strip_orig();

        let reg_cmp_result =
            comparator.compare_registers(&mut checker_regs, &mut reference_registers)?;

        match reg_cmp_result {
            RegisterComparsionResult::NoResult => {
                if checker_regs != reference_registers {
                    error!("Register differs for epoch {}", self.checkpoint_start.epoch);
                    error!("Checker registers:\n{}", checker_regs.dump());
                    error!("Reference registers:\n{}", reference_registers.dump());

                    return Ok((Err(CheckFailReason::RegisterMismatch), nr_dirty_pages));
                }
            }
            RegisterComparsionResult::Pass => (),
            RegisterComparsionResult::Fail => {
                return Ok((Err(CheckFailReason::RegisterMismatch), nr_dirty_pages))
            }
        }

        let checker_writable_ranges = checker_process.get_writable_ranges()?;
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
            page_diff(checker_process, (*reference_borrowed).as_ref(), &dpa_merged)
        })?? {
            error!("Memory differs for epoch {}", self.checkpoint_start.epoch);
            return Ok((Err(CheckFailReason::MemoryMismatch), nr_dirty_pages));
        }

        Ok((Ok(()), nr_dirty_pages))
    }

    /// Mark this segment as "checked" without comparing dirty memory.
    pub fn mark_as_checked(&mut self, has_errors: bool) {
        if has_errors {
            self.checker.mark_as_crashed(Error::Other);
        } else {
            self.checker.mark_as_checked(None);
        }
    }

    /// Get the reference process at the start of the segment.
    pub fn reference_start<'a>(&'a self) -> MutexGuard<'a, DetachedProcess<OwnedProcess>> {
        self.checkpoint_start.process.lock()
    }

    /// Get the reference process at the end of the segment, it it exists.
    pub fn reference_end<'a>(&'a self) -> Option<MutexGuard<'a, DetachedProcess<OwnedProcess>>> {
        self.status.checkpoint_end().map(|c| c.process.lock())
    }

    pub fn has_errors(&self) -> bool {
        if matches!(self.status, SegmentStatus::Crashed) {
            true
        } else if matches!(
            self.checker.status,
            CheckerStatus::Crashed(..) | CheckerStatus::Checked(Some(..))
        ) {
            true
        } else {
            false
        }
    }

    pub fn is_checked(&self) -> bool {
        self.checker.is_finished()
    }
}
