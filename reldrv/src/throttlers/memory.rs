use log::info;

use crate::{
    check_coord::{CheckCoordinator, ProcessRole},
    dirty_page_trackers::{DirtyPageAddressTracker, DirtyPageAddressTrackerContext},
    dispatcher::{Module, Subscribers},
    process::PAGESIZE,
    segments::SegmentChains,
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
        segments: &SegmentChains,
    ) -> usize {
        (nr_dirty_pages_current_segment + segments.nr_dirty_pages()) * *PAGESIZE as usize * 2
    }
}

impl Throttler for MemoryBasedThrottler {
    fn should_throttle(&self, segments: &SegmentChains, check_coord: &CheckCoordinator) -> bool {
        if self.memory_overhead_watermark == 0 {
            return false;
        }

        let memory_overhead = Self::get_potential_memory_overhead(
            check_coord
                .dispatcher
                .nr_dirty_pages(
                    ProcessRole::Main,
                    &DirtyPageAddressTrackerContext {
                        segment: &*segments.last_segment().unwrap().read(), // TODO: Not needed
                        main_pid: check_coord.main.pid,
                    },
                )
                .unwrap(),
            segments,
        );

        info!(
            "Potential memory overhead: {}",
            human_bytes::human_bytes(memory_overhead as f64)
        );

        memory_overhead > self.memory_overhead_watermark
    }

    fn should_unthrottle(&self, segments: &SegmentChains, _check_coord: &CheckCoordinator) -> bool {
        let memory_overhead = Self::get_potential_memory_overhead(0, segments);

        memory_overhead <= self.memory_overhead_watermark
    }
}

impl Module for MemoryBasedThrottler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_throttler(self);
    }
}
