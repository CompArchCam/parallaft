use crate::{check_coord::CheckCoordinator, error::Result, types::process_id::Main};

pub mod legacy;
pub mod relrtlib;

pub trait ScheduleCheckpoint {
    /// Schedule a checkpoint to be taken as soon as possible.
    fn schedule_checkpoint(&self, main: &mut Main, check_coord: &CheckCoordinator) -> Result<()>;
}

pub trait ScheduleCheckpointReady {
    fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()>;
}
