pub mod fpt;
pub mod soft_dirty;

use std::ops::Range;

use bitflags::bitflags;
use nix::unistd::Pid;

use crate::{
    check_coord::ProcessRole,
    error::Result,
    segments::{Segment, SegmentId},
};

bitflags! {
    pub struct DirtyPageAddressFlags: u32 {
        const CONTAINS_WR_ONLY = 0b1;
    }
}

pub struct DirtyPageAddressTrackerContext<'a> {
    pub segment: &'a Segment,
    pub main_pid: Pid,
}

#[allow(unused_variables)]
pub trait DirtyPageAddressTracker {
    fn take_dirty_pages_addresses<'a>(
        &self,
        segment_id: SegmentId,
        role: ProcessRole,
        ctx: &DirtyPageAddressTrackerContext<'a>,
    ) -> Result<(Box<dyn AsRef<[usize]>>, DirtyPageAddressFlags)>;
}

#[allow(unused_variables)]
pub trait ExtraWritableRangesProvider {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]>;
}
