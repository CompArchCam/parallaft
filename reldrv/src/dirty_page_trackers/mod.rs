pub mod fpt;
pub mod soft_dirty;

use nix::unistd::Pid;
use std::ops::Range;

use crate::{
    check_coord::ProcessRole,
    error::Result,
    segments::{Segment, SegmentId},
};

#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyPageAddressFlags {
    pub contains_writable_only: bool,
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

    fn nr_dirty_pages<'a>(
        &self,
        role: ProcessRole,
        ctx: &DirtyPageAddressTrackerContext<'a>,
    ) -> Result<usize>;
}

#[allow(unused_variables)]
pub trait ExtraWritableRangesProvider {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]>;
}
