use crate::{check_coord::CheckCoordinator, types::chains::SegmentChains};

pub mod checkpoint_sync;
pub mod memory;
pub mod nr_segments;

pub trait Throttler {
    fn should_throttle(&self, segments: &SegmentChains, check_coord: &CheckCoordinator) -> bool;
    fn should_unthrottle(&self, segments: &SegmentChains, check_coord: &CheckCoordinator) -> bool;
}
