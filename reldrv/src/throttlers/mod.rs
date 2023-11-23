use crate::{check_coord::CheckCoordinator, segments::SegmentChain};

pub mod memory;
pub mod nr_segments;

pub trait Throttler {
    fn should_throttle(
        &self,
        nr_dirty_pages: usize,
        segments: &SegmentChain,
        check_coord: &CheckCoordinator,
    ) -> bool;
    fn should_unthrottle(&self, segments: &SegmentChain, check_coord: &CheckCoordinator) -> bool;
}
