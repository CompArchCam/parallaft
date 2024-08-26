use crate::{
    check_coord::CheckCoordinator,
    process::state::{Running, Stopped},
    types::{chains::SegmentChains, process_id::Main},
};

pub mod checkpoint_sync;
pub mod memory;
pub mod nr_checkers;
pub mod nr_segments;

pub trait Throttler {
    fn should_throttle(
        &self,
        main: &mut Main<Stopped>,
        segments: &SegmentChains,
        check_coord: &CheckCoordinator,
    ) -> bool;
    fn should_unthrottle(
        &self,
        main: &mut Main<Running>,
        segments: &SegmentChains,
        check_coord: &CheckCoordinator,
    ) -> bool;
}
