use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::Range;
use std::sync::Arc;

use itertools::Itertools;
use log::{debug, error, info};
use parking_lot::{Condvar, MappedMutexGuard, Mutex, MutexGuard};

use crate::dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressesWithFlags};
use crate::error::{Error, Result};
use crate::events::comparator::{
    MemoryComparator, MemoryComparsionResult, RegisterComparator, RegisterComparsionResult,
};
use crate::process::detach::Detached;
use crate::process::dirty_pages::merge_page_addresses;
use crate::process::state::{Stopped, Unowned, WithProcess};
use crate::process::{Process, PAGESIZE};

use super::checker::{CheckFailReason, CheckerStatus};
use super::checkpoint::Checkpoint;
use super::process_id::{Checker, InferiorId};
use super::segment_record::SegmentRecord;
use crate::process::registers::RegisterAccess;

pub type SegmentId = u32;

#[derive(Debug)]
pub enum SegmentStatus {
    /// The main process is running on this segment.
    Filling {
        process: Process<Unowned>,
        blocked: bool,
    },

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

    pub fn process(&self) -> Option<Process<Unowned>> {
        match self {
            SegmentStatus::Filling { process, .. } => Some(process.clone()),
            SegmentStatus::Filled { checkpoint, .. } => {
                Some(checkpoint.process.lock().as_ref().unwrap().unowned_copy())
            }
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

impl Display for Segment {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "[S{:>6}]", self.nr)
    }
}

impl Segment {
    pub fn new(
        checkpoint_start: Arc<Checkpoint>,
        nr: SegmentId,
        main: Process<Unowned>,
        enable_async_events: bool,
    ) -> Self {
        Self {
            nr,
            checkpoint_start,
            status: Mutex::new(SegmentStatus::Filling {
                process: main,
                blocked: false,
            }),
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
    pub fn start_checker(&self, checker_cpu_set: Vec<usize>) -> Result<Process<Stopped>> {
        // self.record.rewind(self)?; // TODO:
        self.checker_status
            .lock()
            .start(&self.checkpoint_start, checker_cpu_set)
    }

    fn get_main_dirty_page_addresses_once(
        self: &Arc<Self>,
        dirty_page_tracker: &dyn DirtyPageAddressTracker,
        extra_writable_ranges: &[Range<usize>],
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
                            .take_dirty_pages_addresses(
                                InferiorId::Main(Some(self.clone())),
                                extra_writable_ranges,
                            )
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
        mut checker_process: Process<Stopped>,
        mut reference_process: Process<Stopped>,
        ignored_pages: &[usize],
        _extra_writable_ranges: &[Range<usize>],
        comparator: &dyn MemoryComparator,
    ) -> Result<(Process<Stopped>, Process<Stopped>, Option<CheckFailReason>)> {
        let dpa_merged = merge_page_addresses(
            &dpa_main.addresses,
            &dpa_checker.addresses,
            &ignored_pages
                .iter()
                .map(|&x| x..x + *PAGESIZE)
                .collect_vec(),
        );

        let checker_writable_ranges = checker_process.get_writable_ranges()?;
        let reference_writable_ranges = reference_process.get_writable_ranges()?;

        if checker_writable_ranges != reference_writable_ranges {
            error!(
                "Memory map differs for epoch {}",
                self.checkpoint_start.epoch
            );
            return Ok((
                checker_process,
                reference_process,
                Some(CheckFailReason::MemoryMapMismatch),
            ));
        }

        if !dpa_main.flags.contains_writable_only || !dpa_checker.flags.contains_writable_only {
            // let writable_ranges = checker_writable_ranges
            //     .iter()
            //     .chain(extra_writable_ranges)
            //     .cloned()
            //     .collect::<Vec<_>>();
            // dpa_merged = filter_writable_addresses(dpa_merged, &writable_ranges);

            todo!();
        }

        debug!("Comparing {} dirty pages", dpa_merged.len());

        let result;
        (checker_process, reference_process, result) =
            comparator.compare_memory(&dpa_merged, checker_process, reference_process)?;

        match result {
            MemoryComparsionResult::Pass => Ok((checker_process, reference_process, None)),
            MemoryComparsionResult::Fail { mismatching_pages } => {
                error!("Memory differs, mismatching pages: {:?}", mismatching_pages);
                return Ok((
                    checker_process,
                    reference_process,
                    Some(CheckFailReason::MemoryMismatch),
                ));
            }
        }
    }

    fn compare_registers<C: RegisterAccess, R: RegisterAccess>(
        &self,
        checker_process: C,
        reference_process: R,
        comparator: &dyn RegisterComparator,
    ) -> Result<(C, R, Option<CheckFailReason>)> {
        let (checker_process, mut checker_regs) = checker_process.read_registers_precisely()?;
        checker_regs = checker_regs.strip_orig().with_resume_flag_cleared();

        let (reference_process, mut reference_regs) =
            reference_process.read_registers_precisely()?;
        reference_regs = reference_regs.strip_orig().with_resume_flag_cleared();

        let reg_cmp_result =
            comparator.compare_registers(&mut checker_regs, &mut reference_regs)?;

        let result = match reg_cmp_result {
            RegisterComparsionResult::NoResult => {
                if checker_regs != reference_regs {
                    error!("Register differs");
                    error!("Checker registers:\n{}", checker_regs.dump());
                    error!("Reference registers:\n{}", reference_regs.dump());

                    Some(CheckFailReason::RegisterMismatch)
                } else {
                    None
                }
            }
            RegisterComparsionResult::Pass => None,
            RegisterComparsionResult::Fail => Some(CheckFailReason::RegisterMismatch),
        };

        Ok((checker_process, reference_process, result))
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
        checker: &mut Checker<Stopped>,
        ignored_pages: &[usize],
        extra_writable_ranges: &[Range<usize>],
        dirty_page_tracker: &dyn DirtyPageAddressTracker,
        register_comparator: &dyn RegisterComparator,
        memory_comparator: &dyn MemoryComparator,
    ) -> Result<Option<CheckFailReason>> {
        info!("{checker} Checking");

        self.wait_until_main_finished()?;

        let dpa_main =
            self.get_main_dirty_page_addresses_once(dirty_page_tracker, extra_writable_ranges)?;
        let dpa_checker = Arc::new(dirty_page_tracker.take_dirty_pages_addresses(
            InferiorId::Checker(self.clone()),
            extra_writable_ranges,
        )?);

        debug!("Main dirty pages: {}", dpa_main.nr_dirty_pages());
        debug!("Checker dirty pages: {}", dpa_checker.nr_dirty_pages());

        let result = (|| {
            let checkpoint_end = self
                .status
                .lock()
                .checkpoint_end()
                .expect("Invalid segment status");

            let mut ref_process_mg = checkpoint_end.process.lock();
            let mut ref_process = ref_process_mg.take().unwrap();

            let result;
            (ref_process, result) = checker.try_map_process_inplace(|chk_process| {
                let WithProcess(ref_process, (chk_process, result)) =
                    ref_process.try_borrow_with(|ref_process_attached| {
                        let (chk_process, ref_process_attached, result) = self.compare_registers(
                            chk_process,
                            ref_process_attached,
                            register_comparator,
                        )?;

                        if let Some(reason) = result {
                            return Ok(WithProcess(
                                ref_process_attached,
                                (chk_process, Some(reason)),
                            ));
                        }

                        let (chk_process, ref_process_attached, result) = self.compare_memory(
                            &dpa_main,
                            &dpa_checker,
                            chk_process,
                            ref_process_attached,
                            ignored_pages,
                            extra_writable_ranges,
                            memory_comparator,
                        )?;

                        Ok(WithProcess(ref_process_attached, (chk_process, result)))
                    })?;

                Ok::<_, crate::error::Error>(WithProcess(chk_process, (ref_process, result)))
            })?;

            *ref_process_mg = Some(ref_process);

            Ok::<_, Error>(result)
        })()?;

        *self.checker_status.lock() = CheckerStatus::Checked {
            result,
            dirty_page_addresses: dpa_checker,
        };

        Ok(result)
    }

    /// Get the reference process at the start of the segment.
    pub fn reference_start(&self) -> MappedMutexGuard<'_, Process<Detached>> {
        MutexGuard::map(self.checkpoint_start.process.lock(), |x| {
            x.as_mut().unwrap()
        })
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
