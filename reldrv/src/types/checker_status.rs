use std::{fmt::Display, sync::Arc};

use crate::{
    dirty_page_trackers::DirtyPageAddressesWithFlags,
    error::{Error, Result},
    process::{
        state::{Stopped, Unowned, WithProcess},
        Process,
    },
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
        process: Process<Unowned>,
        cpu_set: Vec<usize>,
    },
    Checked {
        result: Option<CheckFailReason>,
        dirty_page_addresses: Arc<DirtyPageAddressesWithFlags>,
    },
    Crashed(Error),
}

impl Display for CheckerStatus {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            CheckerStatus::NotReady => write!(f, "NotReady"),
            CheckerStatus::Executing { .. } => write!(f, "Executing"),
            CheckerStatus::Checked { .. } => write!(f, "Checked"),
            CheckerStatus::Crashed(err) => write!(f, "Crashed: {}", err),
        }
    }
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
    ) -> Result<Process<Stopped>> {
        let mut ref_process = from_checkpoint.process.lock();

        let WithProcess(new_ref_process, chk_process) = ref_process
            .take()
            .unwrap()
            .try_borrow_with(|p2| p2.fork(true, true))?;

        *ref_process = Some(new_ref_process);

        *self = CheckerStatus::Executing {
            process: chk_process.unowned_copy(),
            cpu_set,
        };

        Ok(chk_process)
    }

    pub fn process(&self) -> Option<&Process<Unowned>> {
        match self {
            CheckerStatus::Executing { process, .. } => Some(process),
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

    pub fn set_cpu_set(&mut self, new_cpu_set: Vec<usize>) -> Result<()> {
        match self {
            CheckerStatus::Executing { cpu_set, .. } => {
                *cpu_set = new_cpu_set;
                Ok(())
            }
            _ => Err(Error::InvalidState),
        }
    }
}
