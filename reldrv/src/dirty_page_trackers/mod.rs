pub mod fpt;
pub mod soft_dirty;

use nix::unistd::Pid;
use std::ops::Range;

use crate::{
    check_coord::ProcessRole,
    error::Result,
    types::segment::{Segment, SegmentId},
};

#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyPageAddressFlags {
    pub contains_writable_only: bool,
}

pub struct DirtyPageAddressTrackerContext<'a> {
    pub segment: &'a Segment,
    pub main_pid: Pid,
}

pub type DirtyPageAddresses = (Box<dyn AsRef<[usize]>>, DirtyPageAddressFlags);

#[allow(unused_variables)]
pub trait DirtyPageAddressTracker {
    fn take_dirty_pages_addresses(
        &self,
        segment_id: SegmentId,
        role: ProcessRole,
        ctx: &DirtyPageAddressTrackerContext<'_>,
    ) -> Result<DirtyPageAddresses>;

    fn nr_dirty_pages(
        &self,
        role: ProcessRole,
        ctx: &DirtyPageAddressTrackerContext<'_>,
    ) -> Result<usize>;
}

#[allow(unused_variables)]
pub trait ExtraWritableRangesProvider {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]>;
}
