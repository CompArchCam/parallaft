use crate::{
    check_coord::CheckCoordinator,
    types::{chains::SegmentChains, process_id::Main},
};

pub mod checkpoint_sync;
pub mod memory;
pub mod nr_checkers;
pub mod nr_segments;

pub trait Throttler {
    fn should_throttle(
        &self,
        main: &mut Main,
        segments: &SegmentChains,
        check_coord: &CheckCoordinator,
    ) -> bool;
    fn should_unthrottle(
        &self,
        main: &mut Main,
        segments: &SegmentChains,
        check_coord: &CheckCoordinator,
    ) -> bool;
}
