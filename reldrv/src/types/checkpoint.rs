use parking_lot::Mutex;

use crate::process::{detach::DetachedProcess, OwnedProcess};

pub type EpochId = u32;

// Who made the checkpoint request
#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum CheckpointCaller {
    Child,
    Shell,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub process: Mutex<DetachedProcess<OwnedProcess>>,
    pub caller: CheckpointCaller,
    pub epoch: EpochId,
}

impl Checkpoint {
    pub fn new(epoch: EpochId, reference: OwnedProcess, caller: CheckpointCaller) -> Self {
        Self {
            epoch,
            caller,
            process: Mutex::new(
                DetachedProcess::detach_from(reference).expect("Failed to detach process"),
            ),
        }
    }
}
