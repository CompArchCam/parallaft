use std::fmt::Debug;
use std::hash::Hash;
use std::ops::Range;
use std::sync::Arc;

use log::{error, info};
use nix::unistd::Pid;
use parking_lot::{Condvar, Mutex, MutexGuard};

use crate::dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressesWithFlags};
use crate::error::{Error, Result};
use crate::events::comparator::{RegisterComparator, RegisterComparsionResult};
use crate::process::detach::DetachedProcess;
use crate::process::dirty_pages::{filter_writable_addresses, merge_page_addresses, page_diff};
use crate::process::{OwnedProcess, Process};

use super::checker::{CheckFailReason, CheckerStatus};
use super::checkpoint::Checkpoint;
use super::process_id::{Checker, InferiorId};
use super::segment_record::SegmentRecord;

pub type SegmentId = u32;

#[derive(Debug)]
pub enum SegmentStatus {
    /// The main process is running on this segment.
    Filling { pid: Pid },

    /// The main process finished this segment, so that the record is fully
    /// filled.
    Filled {
        checkpoint: Arc<Checkpoint>,
        dirty_page_addresses: Option<Arc<DirtyPageAddressesWithFlags>>,
    },

    /// Something went wrong.
    Crashed,
}

impl SegmentStatus {
    pub fn checkpoint_end(&self) -> Option<Arc<Checkpoint>> {
        match self {
            SegmentStatus::Filled { checkpoint, .. } => Some(checkpoint.clone()),
            _ => None,
        }
    }

    pub fn pid(&self) -> Option<Pid> {
        match self {
            SegmentStatus::Filling { pid } => Some(*pid),
            SegmentStatus::Filled { checkpoint, .. } => Some(checkpoint.process.lock().pid),
            SegmentStatus::Crashed => None,
        }
    }
}

#[derive(Debug)]
pub struct Segment {
    pub nr: SegmentId,
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: Mutex<SegmentStatus>,
    pub status_cvar: Condvar,
    pub record: SegmentRecord,
    pub checker_status: Mutex<CheckerStatus>,
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
        Some(self.cmp(other))
    }
}

impl Ord for Segment {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        self.nr.cmp(&other.nr)
    }
}

impl Segment {
    pub fn new(
        checkpoint_start: Arc<Checkpoint>,
        nr: SegmentId,
        main_pid: Pid,
        enable_async_events: bool,
    ) -> Self {
        Self {
            nr,
            checkpoint_start,
            status: Mutex::new(SegmentStatus::Filling { pid: main_pid }),
            status_cvar: Condvar::new(),
            record: SegmentRecord::new(enable_async_events),
            checker_status: Mutex::new(CheckerStatus::new()),
        }
    }

    pub fn mark_main_as_completed(&self, checkpoint_end: Arc<Checkpoint>) {
        let mut status = self.status.lock();
        assert!(matches!(&*status, SegmentStatus::Filling { .. }));
        *status = SegmentStatus::Filled {
            checkpoint: checkpoint_end,
            dirty_page_addresses: None,
        };
        drop(status);
        self.status_cvar.notify_all();
    }

    pub fn mark_as_crashed(&self) {
        let mut status = self.status.lock();
        assert!(matches!(&*status, SegmentStatus::Filling { .. }));
        *status = SegmentStatus::Crashed;
        drop(status);
        self.status_cvar.notify_all();

        self.record.mark_main_as_crashed();
        *self.checker_status.lock() = CheckerStatus::Crashed(Error::Cancelled);
    }

    pub fn mark_as_crashed_if_filling(&self) {
        let mut status = self.status.lock();
        if matches!(&*status, SegmentStatus::Filling { .. }) {
            *status = SegmentStatus::Crashed;
            drop(status);
            self.status_cvar.notify_all();

            self.record.mark_main_as_crashed();
            *self.checker_status.lock() = CheckerStatus::Crashed(Error::Cancelled);
        }
    }

    // Locks: record -> checker
    pub fn start_checker(&self) -> Result<OwnedProcess> {
        // self.record.rewind(self)?; // TODO:
        self.checker_status.lock().start(&self.checkpoint_start)
    }

    fn get_main_dirty_page_addresses_once(
        self: &Arc<Self>,
        dirty_page_tracker: &dyn DirtyPageAddressTracker,
    ) -> Result<Arc<DirtyPageAddressesWithFlags>> {
        let mut status = self.status.lock();

        if let SegmentStatus::Filled {
            dirty_page_addresses,
            ..
        } = &mut *status
        {
            match dirty_page_addresses {
                Some(a) => Ok(a.clone()),
                None => {
                    let new_dirty_page_addresses = MutexGuard::unlocked(&mut status, || {
                        dirty_page_tracker
                            .take_dirty_pages_addresses(InferiorId::Main(Some(self.clone())))
                            .map(Arc::new)
                    })?;

                    Ok(match &mut *status {
                        SegmentStatus::Filled {
                            dirty_page_addresses,
                            ..
                        } => dirty_page_addresses
                            .insert(new_dirty_page_addresses)
                            .clone(),
                        _ => panic!("Unexpected state"),
                    })
                }
            }
        } else {
            panic!("Invalid main status: {:?}", &*status)
        }
    }

    fn compare_memory(
        self: &Arc<Self>,
        dpa_main: &DirtyPageAddressesWithFlags,
        dpa_checker: &DirtyPageAddressesWithFlags,
        checker_process: &Process,
        reference_process: &mut DetachedProcess<impl AsRef<Process>>,
        ignored_pages: &[usize],
        extra_writable_ranges: &[Range<usize>],
    ) -> Result<Option<CheckFailReason>> {
        let mut dpa_merged = merge_page_addresses(
            dpa_main.addresses.as_ref().as_ref(),
            dpa_checker.addresses.as_ref().as_ref(),
            ignored_pages,
        );

        let checker_writable_ranges = checker_process.get_writable_ranges()?;
        let reference_writable_ranges = reference_process.get_writable_ranges()?;

        if checker_writable_ranges != reference_writable_ranges {
            error!(
                "Memory map differs for epoch {}",
                self.checkpoint_start.epoch
            );
            return Ok(Some(CheckFailReason::MemoryMapMismatch));
        }

        if !dpa_main.flags.contains_writable_only || !dpa_checker.flags.contains_writable_only {
            let writable_ranges = checker_writable_ranges
                .iter()
                .chain(extra_writable_ranges)
                .cloned()
                .collect::<Vec<_>>();

            dpa_merged = filter_writable_addresses(dpa_merged, &writable_ranges);
        }

        if !reference_process.borrow_with(|reference_borrowed| {
            page_diff(checker_process, (*reference_borrowed).as_ref(), &dpa_merged)
        })?? {
            error!("Memory differs for epoch {}", self.checkpoint_start.epoch);
            return Ok(Some(CheckFailReason::MemoryMismatch));
        }

        Ok(None)
    }

    fn compare_registers(
        &self,
        checker_process: &Process,
        reference_process: &mut DetachedProcess<OwnedProcess>,
        comparator: &dyn RegisterComparator,
    ) -> Result<Option<CheckFailReason>> {
        let mut checker_regs = checker_process.read_registers_precise()?.strip_orig();
        let mut reference_registers = reference_process
            .borrow_with(|p2| p2.read_registers())??
            .strip_orig();

        let reg_cmp_result =
            comparator.compare_registers(&mut checker_regs, &mut reference_registers)?;

        match reg_cmp_result {
            RegisterComparsionResult::NoResult => {
                if checker_regs != reference_registers {
                    error!("Register differs");
                    error!("Checker registers:\n{}", checker_regs.dump());
                    error!("Reference registers:\n{}", reference_registers.dump());

                    Ok(Some(CheckFailReason::RegisterMismatch))
                } else {
                    Ok(None)
                }
            }
            RegisterComparsionResult::Pass => Ok(None),
            RegisterComparsionResult::Fail => Ok(Some(CheckFailReason::RegisterMismatch)),
        }
    }

    fn wait_until_main_finished(&self) -> Result<()> {
        let mut status = self.status.lock();

        loop {
            match &*status {
                SegmentStatus::Filling { .. } => (),
                SegmentStatus::Filled { .. } => break,
                SegmentStatus::Crashed => return Err(Error::Cancelled),
            }
            self.status_cvar.wait(&mut status);
        }
        Ok(())
    }

    /// Compare dirty memory of the checker process and the reference process
    /// without marking the segment status as checked. This should be called
    /// after the checker process invokes the checkpoint syscall.
    pub fn check(
        self: &Arc<Self>,
        checker: &mut Checker,
        ignored_pages: &[usize],
        extra_writable_ranges: &[Range<usize>],
        dirty_page_tracker: &dyn DirtyPageAddressTracker,
        comparator: &dyn RegisterComparator,
    ) -> Result<Option<CheckFailReason>> {
        info!("{checker} Checking");

        self.wait_until_main_finished()?;

        let dpa_main = self.get_main_dirty_page_addresses_once(dirty_page_tracker)?;
        let dpa_checker = Arc::new(
            dirty_page_tracker.take_dirty_pages_addresses(InferiorId::Checker(self.clone()))?,
        );

        let result = (|| {
            let checkpoint_end = self
                .status
                .lock()
                .checkpoint_end()
                .expect("Invalid segment status");

            let mut reference_process = checkpoint_end.process.lock();

            info!("{checker} Comparing registers");
            let result =
                self.compare_registers(&checker.process, &mut reference_process, comparator)?;

            if let Some(reason) = result {
                return Ok(Some(reason));
            }

            info!("{checker} Comparing memory");
            let result = self.compare_memory(
                &dpa_main,
                &dpa_checker,
                &checker.process,
                &mut reference_process,
                ignored_pages,
                extra_writable_ranges,
            )?;

            if let Some(reason) = result {
                return Ok(Some(reason));
            }

            Ok::<_, Error>(None)
        })()?;

        *self.checker_status.lock() = CheckerStatus::Checked {
            result,
            dirty_page_addresses: dpa_checker,
        };

        Ok(result)
    }

    /// Get the reference process at the start of the segment.
    pub fn reference_start(&self) -> MutexGuard<'_, DetachedProcess<OwnedProcess>> {
        self.checkpoint_start.process.lock()
    }

    pub fn checkpoint_end(&self) -> Option<Arc<Checkpoint>> {
        self.status.lock().checkpoint_end()
    }

    pub fn is_main_finished(&self) -> bool {
        match &*self.status.lock() {
            SegmentStatus::Filling { .. } => false,
            SegmentStatus::Filled { .. } => true,
            SegmentStatus::Crashed => true,
        }
    }

    pub fn is_both_finished(&self) -> bool {
        self.is_main_finished() && self.checker_status.lock().is_finished()
    }
}
