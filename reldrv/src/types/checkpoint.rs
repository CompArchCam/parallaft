use parking_lot::Mutex;

use crate::{
    error::Result,
    process::{detach::Detached, state::Stopped, Process},
};

pub type EpochId = u32;

// Who made the checkpoint request
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CheckpointCaller {
    Child,
    Shell,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub process: Mutex<Option<Process<Detached>>>,
    pub caller: CheckpointCaller,
    pub epoch: EpochId,
}

impl Checkpoint {
    pub fn new(
        epoch: EpochId,
        reference: Process<Stopped>,
        caller: CheckpointCaller,
    ) -> Result<Self> {
        let detached = reference.detach()?;

        Ok(Self {
            epoch,
            caller,
            process: Mutex::new(Some(detached)),
        })
    }
}
