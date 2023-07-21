use crate::check_coord::CheckCoordinator;

pub mod memory;
pub mod nr_segments;

pub trait Throttler {
    fn should_throttle(&self, nr_dirty_pages: usize, check_coord: &CheckCoordinator) -> bool;
    fn should_unthrottle(&self, check_coord: &CheckCoordinator) -> bool;
}
