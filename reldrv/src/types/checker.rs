use std::sync::Arc;

use nix::unistd::Pid;

use crate::{
    dirty_page_trackers::DirtyPageAddressesWithFlags,
    error::{Error, Result},
    process::OwnedProcess,
};

use super::checkpoint::Checkpoint;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum CheckFailReason {
    MemoryMapMismatch,
    MemoryMismatch,
    RegisterMismatch,
}

#[derive(Debug)]
pub enum CheckerStatus {
    NotReady,
    Executing {
        pid: Pid,
        cpu_set: Vec<usize>,
    },
    Checked {
        result: Option<CheckFailReason>,
        dirty_page_addresses: Arc<DirtyPageAddressesWithFlags>,
    },
    Crashed(Error),
}

impl CheckerStatus {
    pub fn new() -> Self {
        Self::NotReady
    }

    pub fn assume_checked(&mut self) {
        *self = CheckerStatus::Checked {
            result: None,
            dirty_page_addresses: Arc::new(DirtyPageAddressesWithFlags::empty()),
        };
    }

    pub fn start(
        &mut self,
        from_checkpoint: &Checkpoint,
        cpu_set: Vec<usize>,
    ) -> Result<OwnedProcess> {
        let mut ref_process = from_checkpoint.process.lock();
        let checker_process = ref_process.borrow_with(|p| p.fork(true, true))??;
        *self = CheckerStatus::Executing {
            pid: checker_process.pid,
            cpu_set,
        };

        Ok(checker_process)
    }

    pub fn pid(&self) -> Option<Pid> {
        match self {
            CheckerStatus::Executing { pid, .. } => Some(*pid),
            _ => None,
        }
    }

    /// Returns whether the checker has finished segment, either successfully or
    /// not.
    pub fn is_finished(&self) -> bool {
        matches!(
            self,
            CheckerStatus::Checked { .. } | CheckerStatus::Crashed(..)
        )
    }

    pub fn cpu_set(&self) -> Option<&[usize]> {
        match self {
            CheckerStatus::Executing { cpu_set, .. } => Some(cpu_set),
            _ => None,
        }
    }
}
