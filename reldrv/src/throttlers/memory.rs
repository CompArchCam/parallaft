use log::info;

use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Dispatcher, Installable},
    process::PAGESIZE,
    segments::SegmentChain,
};

use super::Throttler;

pub struct MemoryBasedThrottler {
    /// Memory overhead watermark in bytes.
    memory_overhead_watermark: usize,
}

impl MemoryBasedThrottler {
    pub fn new(memory_overhead_watermark: usize) -> Self {
        MemoryBasedThrottler {
            memory_overhead_watermark,
        }
    }

    pub fn get_potential_memory_overhead(
        nr_dirty_pages_current_segment: usize,
        segments: &SegmentChain,
    ) -> usize {
        (nr_dirty_pages_current_segment + segments.nr_dirty_pages()) * *PAGESIZE as usize * 2
    }
}

impl Throttler for MemoryBasedThrottler {
    fn should_throttle(
        &self,
        nr_dirty_pages: usize,
        segments: &SegmentChain,
        _check_coord: &CheckCoordinator,
    ) -> bool {
        if self.memory_overhead_watermark == 0 {
            return false;
        }

        let memory_overhead = Self::get_potential_memory_overhead(nr_dirty_pages, segments);

        info!(
            "Potential memory overhead: {}",
            human_bytes::human_bytes(memory_overhead as f64)
        );

        memory_overhead > self.memory_overhead_watermark
    }

    fn should_unthrottle(&self, segments: &SegmentChain, _check_coord: &CheckCoordinator) -> bool {
        let memory_overhead = Self::get_potential_memory_overhead(0, segments);

        memory_overhead <= self.memory_overhead_watermark
    }
}

impl<'a> Installable<'a> for MemoryBasedThrottler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_throttler(self);
    }
}
