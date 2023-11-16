use crate::{check_coord::CheckCoordinator, error::Result};

pub mod legacy;
pub mod pmu;
pub mod relrtlib;

pub trait ScheduleCheckpoint {
    /// Schedule a checkpoint to be taken as soon as possible.
    fn schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()>;
}

pub trait ScheduleCheckpointReady {
    fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()>;
}
