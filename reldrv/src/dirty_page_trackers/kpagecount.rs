use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    process::dirty_pages::PageFlagType,
    types::process_id::InferiorId,
};

use super::{DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressesWithFlags};

pub struct KPageCountDirtyPageTracker {
    dont_use_pagemap_scan: bool,
}

impl KPageCountDirtyPageTracker {
    pub fn new(dont_use_pagemap_scan: bool) -> Self {
        Self {
            dont_use_pagemap_scan,
        }
    }
}

impl DirtyPageAddressTracker for KPageCountDirtyPageTracker {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: InferiorId,
        extra_writable_ranges: &[std::ops::Range<usize>],
    ) -> Result<DirtyPageAddressesWithFlags> {
        let pages = match &inferior_id {
            InferiorId::Main(segment) => segment
                .as_ref()
                .unwrap()
                .checkpoint_end()
                .unwrap()
                .process
                .lock()
                .as_ref()
                .unwrap()
                .get_dirty_pages(
                    PageFlagType::KPageCountEqualsOne,
                    extra_writable_ranges,
                    !self.dont_use_pagemap_scan,
                )?,
            InferiorId::Checker(segment) => segment
                .checker_status
                .lock()
                .process()
                .unwrap()
                .get_dirty_pages(
                    PageFlagType::KPageCountEqualsOne,
                    extra_writable_ranges,
                    !self.dont_use_pagemap_scan,
                )?,
        };

        Ok(DirtyPageAddressesWithFlags {
            addresses: pages,
            flags: DirtyPageAddressFlags {
                contains_writable_only: true,
            },
        })
    }
}

impl Module for KPageCountDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
    }
}
