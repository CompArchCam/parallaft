use std::collections::HashMap;
use std::fmt::{Debug, Display};
use std::hash::Hash;
use std::ops::Range;
use std::sync::atomic::AtomicU32;
use std::sync::Arc;

use parking_lot::{Condvar, MappedMutexGuard, Mutex, MutexGuard};

use crate::check_coord::SyscallType;
use crate::dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressesWithFlags};
use crate::error::{Error, Result};
use crate::process::detach::Detached;
use crate::process::state::Unowned;
use crate::process::Process;

use super::checker_exec::{CheckerExecution, CheckerExecutionId};
use super::checkpoint::Checkpoint;
use super::process_id::InferiorId;
use super::segment_record::record::SegmentRecord;

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
        checkpoint: Option<Arc<Checkpoint>>,
        dirty_page_addresses: Option<Arc<DirtyPageAddressesWithFlags>>,
    },

    /// Something went wrong.
    Crashed,
}

impl SegmentStatus {
    pub fn checkpoint_end(&self) -> Option<Arc<Checkpoint>> {
        match self {
            SegmentStatus::Filled { checkpoint, .. } => checkpoint.clone(),
            _ => None,
        }
    }

    pub fn process(&self) -> Option<Process<Unowned>> {
        match self {
            SegmentStatus::Filling { process, .. } => Some(process.clone()),
            SegmentStatus::Filled { checkpoint, .. } => checkpoint
                .as_ref()
                .map(|p| p.process.lock().as_ref().unwrap().unowned_copy()),
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
    pub record: Arc<SegmentRecord>,
    pub main_checker_exec: Arc<CheckerExecution>,
    pub aux_checker_exec: Mutex<HashMap<CheckerExecutionId, Arc<CheckerExecution>>>,
    pub pinned: Mutex<bool>,
    pub ongoing_syscall: Option<SyscallType>,
    exec_id: AtomicU32,
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
        ongoing_syscall: Option<SyscallType>,
        with_active_events: bool,
    ) -> Self {
        let record = Arc::new(SegmentRecord::new(with_active_events));
        Self {
            nr,
            checkpoint_start,
            status: Mutex::new(SegmentStatus::Filling {
                process: main,
                blocked: false,
            }),
            status_cvar: Condvar::new(),
            record: record.clone(),
            main_checker_exec: Arc::new(CheckerExecution::new(0, record.clone())),
            aux_checker_exec: Mutex::new(HashMap::new()),
            pinned: Mutex::new(false),
            ongoing_syscall,
            exec_id: AtomicU32::new(1),
        }
    }

    pub fn mark_main_as_completed(&self, checkpoint_end: Option<Arc<Checkpoint>>) {
        let mut status = self.status.lock();
        assert!(matches!(&*status, SegmentStatus::Filling { .. }));
        *status = SegmentStatus::Filled {
            checkpoint: checkpoint_end,
            dirty_page_addresses: None,
        };
        drop(status);
        self.status_cvar.notify_all();
    }

    pub fn mark_main_as_crashed(&self) {
        let mut status = self.status.lock();
        assert!(matches!(&*status, SegmentStatus::Filling { .. }));
        *status = SegmentStatus::Crashed;
        drop(status);
        self.status_cvar.notify_all();
        self.record.mark_main_as_crashed();
    }

    pub fn mark_main_as_crashed_if_filling(&self) {
        let mut status = self.status.lock();
        if matches!(&*status, SegmentStatus::Filling { .. }) {
            *status = SegmentStatus::Crashed;
            drop(status);
            self.status_cvar.notify_all();
            self.record.mark_main_as_crashed();
        }
    }

    pub fn get_main_dirty_page_addresses_once(
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
            panic!("{self} Invalid main status: {:?}", &*status)
        }
    }

    pub fn wait_until_main_finished(&self) -> Result<()> {
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
        self.is_main_finished() && self.main_checker_exec.is_finished() && !*self.pinned.lock()
    }

    pub fn checker_execs(&self) -> Vec<Arc<CheckerExecution>> {
        let mut result = vec![self.main_checker_exec.clone()];
        result.extend(self.aux_checker_exec.lock().values().cloned());
        result
    }

    pub fn checker_processes(&self) -> Vec<Process<Unowned>> {
        self.checker_execs()
            .iter()
            .filter_map(|x| x.status.lock().process().map(|x| x.clone()))
            .collect()
    }

    pub fn new_checker_exec(&self) -> Arc<CheckerExecution> {
        assert!(*self.pinned.lock());

        let exec = Arc::new(CheckerExecution::new(
            self.exec_id
                .fetch_add(1, std::sync::atomic::Ordering::SeqCst),
            self.record.clone(),
        ));

        self.aux_checker_exec.lock().insert(exec.id, exec.clone());

        exec
    }
}
