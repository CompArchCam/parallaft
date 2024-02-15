#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

use std::collections::LinkedList;
use std::fmt::Debug;
use std::hash::Hash;
use std::ops::{Deref, Range};

use std::sync::Arc;
use std::{mem, ptr};

use log::{error, info};
use nix::unistd::Pid;
use parking_lot::{Mutex, MutexGuard};

use crate::check_coord::ProcessRole;
use crate::dirty_page_trackers::{
    DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressTrackerContext,
};
use crate::error::{Error, Result};
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
    Subsequent { reference: OwnedProcess },
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
            kind: CheckpointKind::Subsequent { reference },
        }
    }

    pub fn initial(epoch: EpochId, caller: CheckpointCaller) -> Self {
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
pub struct Segment {
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: SegmentStatus,
    pub nr: SegmentId,
    pub syscall_log: LinkedList<SavedSyscall>,
    pub ongoing_syscall: Option<SavedIncompleteSyscall>,
    pub trap_event_log: LinkedList<SavedTrapEvent>,
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

            let p1 = checker.deref();
            let p2 = checkpoint_end.reference().unwrap().deref();

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

            let p1_writable_ranges = p1.get_writable_ranges()?;
            let p2_writable_ranges = p2.get_writable_ranges()?;

            if p1_writable_ranges != p2_writable_ranges {
                error!(
                    "Memory map differs for epoch {}",
                    self.checkpoint_start.epoch
                );
                return Ok((Err(CheckFailReason::MemoryMapMismatch), nr_dirty_pages));
            }

            if !dpa_main_flags.contains(DirtyPageAddressFlags::CONTAINS_WR_ONLY)
                || !dpa_checker_flags.contains(DirtyPageAddressFlags::CONTAINS_WR_ONLY)
            {
                let writable_ranges = p1_writable_ranges
                    .into_iter()
                    .chain(extra_writable_ranges.into_iter())
                    .cloned()
                    .collect::<Vec<_>>();

                dpa_merged = filter_writable_addresses(dpa_merged, &writable_ranges);
                nr_dirty_pages = dpa_merged.len();
            }

            info!("Comparing {} dirty pages", nr_dirty_pages);

            if !page_diff(p1, p2, &dpa_merged)? {
                error!("Memory differs for epoch {}", self.checkpoint_start.epoch);
                return Ok((Err(CheckFailReason::MemoryMismatch), nr_dirty_pages));
            }

            let checker_regs = p1.read_registers()?; // can't use read_registers_precise yet due to waitpid race
            let reference_registers = p2.read_registers()?;

            #[cfg(target_arch = "aarch64")]
            let checker_regs = checker_regs.with_x7(reference_registers.x7()); // ignore x7, yet, because we can't read correct x7 in syscall entry

            if checker_regs != reference_registers {
                error!("Register differs for epoch {}", self.checkpoint_start.epoch);
                info!("Checker registers: {:#?}", checker_regs);
                info!("Reference registers: {:#?}", reference_registers);

                info!("Checker backtrace");
                checker.unwind().unwrap();

                info!("Checkpoint backtrace");
                checkpoint_end.reference().unwrap().unwind().unwrap();

                return Ok((Err(CheckFailReason::RegisterMismatch), nr_dirty_pages));
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
    pub fn reference_start<'a>(&'a self) -> Option<&'a Process> {
        self.checkpoint_start.reference().map(|r| r.deref())
    }

    /// Get the reference process at the end of the segment, it it exists.
    pub fn reference_end<'a>(&'a self) -> Option<&'a Process> {
        self.status
            .checkpoint_end()
            .and_then(|c| c.reference().map(|r| r.deref()))
    }

    pub fn has_errors(&self) -> bool {
        match self.status {
            SegmentStatus::Checked { has_errors, .. } => has_errors,
            _ => false,
        }
    }
}

#[derive(Debug)]
pub struct SegmentChain {
    pub list: LinkedList<Arc<Mutex<Segment>>>,
    next_id: SegmentId,
    main_pid: Pid,
}

impl SegmentChain {
    pub fn new(main_pid: Pid) -> Self {
        Self {
            list: LinkedList::new(),
            next_id: 0,
            main_pid,
        }
    }

    /// Get the number of live segments in this segment chain.
    pub fn nr_live_segments(&self) -> usize {
        self.list
            .iter()
            .filter(|s| {
                matches!(
                    s.lock().status,
                    SegmentStatus::Checked { .. } | SegmentStatus::ReadyToCheck { .. }
                )
            })
            .count()
    }

    /// Check if there are any checking errors in this segment chain.
    pub fn has_errors(&self) -> bool {
        self.list.iter().any(|segment| segment.lock().has_errors())
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn last_segment(&self) -> Option<Arc<Mutex<Segment>>> {
        self.list.back().map(|s| s.clone())
    }

    pub fn first_segment(&self) -> Option<Arc<Mutex<Segment>>> {
        self.list.front().map(|s| s.clone())
    }

    pub fn on_chain_head(&self) -> bool {
        match self.list.back() {
            Some(segment) => match segment.lock().status {
                SegmentStatus::New { .. } => false,
                _ => true,
            },
            None => true,
        }
    }

    pub fn add_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        checker: Option<OwnedProcess>,
        on_segment_ready: impl FnOnce(&mut Segment, &Checkpoint) -> Result<bool>,
        on_segment_created: impl FnOnce(&Segment) -> Result<()>,
        on_segment_chain_closed: impl FnOnce(&Segment) -> Result<()>,
        on_cleanup_needed: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let checkpoint = Arc::new(checkpoint);
        let mut do_cleanup = false;

        if let Some(last_segment) = self.list.back() {
            let mut last_segment = last_segment.lock();

            if matches!(last_segment.status, SegmentStatus::New { .. }) {
                last_segment.mark_as_ready(checkpoint.clone())?;
                do_cleanup = on_segment_ready(&mut last_segment, &checkpoint)?;
            }
        }

        if let Some(checker) = checker {
            let segment = Segment::new(checkpoint, checker, self.next_id);
            self.next_id += 1;

            info!("New segment: {:?}", segment);
            on_segment_created(&segment)?;

            self.list.push_back(Arc::new(Mutex::new(segment)));
        } else {
            if let Some(last_segment) = self.list.back() {
                let last_segment = last_segment.lock();
                on_segment_chain_closed(&last_segment)?;
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
                let front = front.lock();
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

    pub fn lookup_segment_checker_with<Ret>(
        &self,
        pid: Pid,
        f: impl FnOnce(MutexGuard<Segment>, Arc<Mutex<Segment>>) -> Ret,
    ) -> Option<Ret> {
        for segment in &self.list {
            let segment_locked = segment.lock();
            if segment_locked.checker().map_or(false, |c| c.pid == pid) {
                return Some(f(segment_locked, segment.clone()));
            }
        }
        None
    }

    pub fn lookup_segment_with<Ret>(
        &self,
        pid: Pid,
        f: impl FnOnce(MutexGuard<Segment>, bool) -> Ret,
    ) -> Option<Ret> {
        if pid == self.main_pid {
            if let Some(last_segment) = self.list.back() {
                let last_segment_locked = last_segment.lock();
                if matches!(last_segment_locked.status, SegmentStatus::New { .. }) {
                    return Some(f(last_segment_locked, true));
                }
            }
        } else {
            return self.lookup_segment_checker_with(pid, |segment, _| f(segment, false));
        }

        None
    }

    pub fn lookup_segment_checker_arc(&self, pid: Pid) -> Option<Arc<Mutex<Segment>>> {
        for segment in &self.list {
            let segment_locked = segment.lock();
            if segment_locked.checker().map_or(false, |c| c.pid == pid) {
                return Some(segment.clone());
            }
        }
        None
    }

    pub fn lookup_segment_checker_mg(&self, pid: Pid) -> Option<MutexGuard<Segment>> {
        for segment in &self.list {
            let segment_locked = segment.lock();
            if segment_locked.checker().map_or(false, |c| c.pid == pid) {
                return Some(segment_locked);
            }
        }
        None
    }

    pub fn lookup_segment_main_mg(&self) -> Option<MutexGuard<Segment>> {
        if let Some(last_segment) = self.list.back() {
            let last_segment_locked = last_segment.lock();
            if matches!(last_segment_locked.status, SegmentStatus::New { .. }) {
                return Some(last_segment_locked);
            }
        }

        None
    }

    pub fn lookup_segment_arc(&self, pid: Pid) -> Option<(Arc<Mutex<Segment>>, bool)> {
        if pid == self.main_pid {
            if let Some(last_segment) = self.list.back() {
                let last_segment_locked = last_segment.lock();
                if matches!(last_segment_locked.status, SegmentStatus::New { .. }) {
                    return Some((last_segment.clone(), true));
                }
            }
        } else {
            return self.lookup_segment_checker_arc(pid).map(|s| (s, false));
        }

        None
    }

    /// Get the total number of dirty pages in this segment chain.
    pub fn nr_dirty_pages(&self) -> usize {
        self.list
            .iter()
            .map(|segment| {
                let segment = segment.lock();
                segment.dirty_page_addresses_main.len()
            })
            .sum()
    }
}

// #[derive(Debug)]
// pub struct SegmentChain {
//     main_pid: Pid,
//     pub inner: RwLock<SegmentListRaw>,
//     nr_segments: AtomicU32,
// }

// #[allow(unused)]
// impl SegmentChain {
//     pub fn new(main_pid: Pid) -> Self {
//         Self {
//             inner: RwLock::new(SegmentListRaw::new(main_pid)),
//             nr_segments: AtomicU32::new(0),
//         }
//     }

//     // pub fn get_last_segment(&self) -> Option<Arc<Mutex<Segment>>> {
//     //     self.inner.read().back().map(|s| s.clone())
//     // }

//     // pub fn get_first_segment(&self) -> Option<Arc<Mutex<Segment>>> {
//     //     self.inner.read().front().map(|s| s.clone())
//     // }

//     pub fn get_segment_by_checker_pid(&self, pid: Pid) -> Option<Arc<Mutex<Segment>>> {
//         self.inner
//             .read()
//             .iter()
//             .find(|&s| s.lock().checker().map_or(false, |c| c.pid == pid))
//             .map(|t| t.clone())
//     }

//     pub fn get_active_segment_by_pid(&self, pid: Pid) -> Option<(Arc<Mutex<Segment>>, bool)> {
//         if pid == self.main_pid {
//             if let Some(last_segment) = self.inner.read().back() {
//                 let last_segment_locked = last_segment.lock();
//                 if matches!(last_segment_locked.status, SegmentStatus::New { .. }) {
//                     return Some((last_segment.clone(), true));
//                 }
//             }
//         } else if let Some(segment) = self.get_segment_by_checker_pid(pid) {
//             return Some((segment, false));
//         } else {
//             return None;
//         }

//         None
//     }

//     pub fn get_active_segment_with<R>(
//         &self,
//         pid: Pid,
//         f: impl FnOnce(&mut Segment, bool) -> R,
//     ) -> Option<R> {
//         self.get_active_segment_by_pid(pid)
//             .map(|(segment, is_main)| f(segment.lock().deref_mut(), is_main))
//     }

//     /// Get the total number of dirty pages in this segment chain.
//     pub fn nr_dirty_pages(&self) -> usize {
//         self.inner
//             .read()
//             .iter()
//             .map(|segment| {
//                 let segment = segment.lock();
//                 segment.nr_dirty_pages().unwrap_or(0)
//             })
//             .sum()
//     }

//     pub fn manipulate(&self) -> SegmentChainReadSession {
//         SegmentChainReadSession {
//             inner: self.inner.upgradable_read(),
//         }
//     }
// }

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
