// Throttle based on the number of live segments.
// Stop the main process when the number of live segments exceeds a limit.

use log::info;

use super::Throttler;
use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Module, Subscribers},
    process::state::{Running, Stopped},
    types::{chains::SegmentChains, process_id::Main},
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
        _main: &mut Main<Stopped>,
        segments: &SegmentChains,
        _check_coord: &CheckCoordinator,
    ) -> bool {
        if self.max_nr_live_segments == 0 {
            return false;
        }

        if segments.nr_live_segments() >= self.max_nr_live_segments {
            info!("Throttling due to too many live segments");
            true
        } else {
            false
        }
    }

    fn should_unthrottle(
        &self,
        _main: &mut Main<Running>,
        segments: &SegmentChains,
        _check_coord: &CheckCoordinator,
    ) -> bool {
        segments.nr_live_segments() <= self.max_nr_live_segments
    }
}

impl Module for NrSegmentsBasedThrottler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_throttler(self);
    }
}
