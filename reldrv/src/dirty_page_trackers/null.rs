use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    types::process_id::InferiorId,
};

use super::{DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressesWithFlags};

pub struct NullDirtyPageTracker;

impl NullDirtyPageTracker {
    pub fn new() -> Self {
        Self
    }
}

impl DirtyPageAddressTracker for NullDirtyPageTracker {
    fn take_dirty_pages_addresses(
        &self,
        _inferior_id: InferiorId,
        _extra_writable_ranges: &[std::ops::Range<usize>],
    ) -> Result<DirtyPageAddressesWithFlags> {
        Ok(DirtyPageAddressesWithFlags {
            addresses: Box::new([]),
            flags: DirtyPageAddressFlags {
                contains_writable_only: true,
            },
        })
    }
}

impl Module for NullDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
    }
}
