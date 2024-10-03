use std::{collections::HashMap, ops::Range};

use log::debug;
use parking_lot::Mutex;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{process_lifetime::HandlerContext, segment::SegmentEventHandler},
    process::{dirty_pages::PageFlagType, state::Stopped},
    types::{
        process_id::{InferiorId, Main},
        segment::SegmentId,
    },
};

use super::{
    DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressesWithFlags,
    ExtraWritableRangesProvider,
};

pub struct KPageCountDirtyPageTracker {
    dont_use_pagemap_scan: bool,
    pages_written_map: Mutex<HashMap<SegmentId, Vec<Range<usize>>>>,
}

impl KPageCountDirtyPageTracker {
    pub fn new(dont_use_pagemap_scan: bool) -> Self {
        Self {
            dont_use_pagemap_scan,
            pages_written_map: Mutex::new(HashMap::new()),
        }
    }
}

impl SegmentEventHandler for KPageCountDirtyPageTracker {
    fn handle_checkpoint_created_pre_fork(
        &self,
        main: &mut Main<Stopped>,
        ctx: HandlerContext,
    ) -> Result<()> {
        if let Some(segment) = &main.segment {
            let pages_written = main.process().get_dirty_pages(
                PageFlagType::KPageCountEqualsOne,
                &ctx.check_coord.dispatcher.get_extra_writable_ranges(),
                !self.dont_use_pagemap_scan,
            )?;

            debug!("{main} Dirty pages: {} segments", pages_written.len());

            self.pages_written_map
                .lock()
                .insert(segment.nr, pages_written);
        }
        Ok(())
    }
}

impl DirtyPageAddressTracker for KPageCountDirtyPageTracker {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: InferiorId,
        extra_writable_ranges: &[std::ops::Range<usize>],
    ) -> Result<DirtyPageAddressesWithFlags> {
        let pages = match &inferior_id {
            InferiorId::Main(Some(segment)) => {
                self.pages_written_map.lock().remove(&segment.nr).unwrap()
            }
            InferiorId::Main(None) => vec![],
            InferiorId::Checker(_, exec) => exec.status.lock().process().unwrap().get_dirty_pages(
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
        subs.install_segment_event_handler(self);
        subs.set_dirty_page_tracker(self);
    }
}
