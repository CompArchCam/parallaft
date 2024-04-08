use crate::{
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
    Checking(OwnedProcess),
    Checked(Option<CheckFailReason>),
    Crashed(Error),
}

#[derive(Debug)]
pub struct Checker {
    pub status: CheckerStatus,
}

impl Checker {
    pub fn new() -> Self {
        Self {
            status: CheckerStatus::NotReady,
        }
    }

    pub fn start(&mut self, from_checkpoint: &Checkpoint) -> Result<&OwnedProcess> {
        let mut ref_process = from_checkpoint.process.lock();

        let checker_process = ref_process.borrow_with(|p| p.fork(true, false))??;

        self.status = CheckerStatus::Checking(checker_process);

        match &self.status {
            CheckerStatus::Checking(p) => Ok(p),
            _ => unreachable!(),
        }
    }

    pub fn mark_as_checked(&mut self, result: Option<CheckFailReason>) {
        self.status = CheckerStatus::Checked(result);
    }

    pub fn mark_as_crashed(&mut self, error: Error) {
        self.status = CheckerStatus::Crashed(error);
    }

    pub fn is_finished(&self) -> bool {
        match self.status {
            CheckerStatus::NotReady => false,
            CheckerStatus::Checking(_) => false,
            CheckerStatus::Checked(_) => true,
            CheckerStatus::Crashed(_) => true,
        }
    }

    pub fn process(&self) -> Option<&OwnedProcess> {
        match &self.status {
            CheckerStatus::Checking(p) => Some(p),
            _ => None,
        }
    }
}
