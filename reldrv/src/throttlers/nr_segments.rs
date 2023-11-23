// Throttle based on the number of live segments.
// Stop the main process when the number of live segments exceeds a limit.

use log::info;

use super::Throttler;
use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Dispatcher, Installable},
    segments::SegmentChain,
};

pub struct NrSegmentsBasedThrottler {
    max_nr_live_segments: usize,
}

impl NrSegmentsBasedThrottler {
    pub fn new(max_nr_live_segments: usize) -> Self {
        Self {
            max_nr_live_segments,
        }
    }
}

impl Throttler for NrSegmentsBasedThrottler {
    fn should_throttle(
        &self,
        _nr_dirty_pages: usize,
        segments: &SegmentChain,
        _check_coord: &CheckCoordinator,
    ) -> bool {
        if self.max_nr_live_segments == 0 {
            return false;
        }

        if segments.nr_live_segments() >= self.max_nr_live_segments - 1 {
            info!("Throttling due to too many live segments");
            true
        } else {
            false
        }
    }

    fn should_unthrottle(&self, segments: &SegmentChain, _check_coord: &CheckCoordinator) -> bool {
        if segments.nr_live_segments() < self.max_nr_live_segments {
            true
        } else {
            false
        }
    }
}

impl<'a> Installable<'a> for NrSegmentsBasedThrottler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_throttler(self);
    }
}
