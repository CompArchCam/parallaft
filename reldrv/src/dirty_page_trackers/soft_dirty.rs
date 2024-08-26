use crate::{
    dispatcher::Module,
    error::Result,
    events::segment::SegmentEventHandler,
    process::{dirty_pages::PageFlag, state::Stopped},
    types::process_id::{Checker, InferiorId, Main},
};

use super::{DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressesWithFlags};

pub struct SoftDirtyPageTracker {
    dont_clear_soft_dirty: bool,
}

impl SoftDirtyPageTracker {
    pub fn new(dont_clear_soft_dirty: bool) -> Self {
        Self {
            dont_clear_soft_dirty,
        }
    }
}

impl DirtyPageAddressTracker for SoftDirtyPageTracker {
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
                .get_dirty_pages(PageFlag::SoftDirty, extra_writable_ranges)?,
            InferiorId::Checker(segment) => segment
                .checker_status
                .lock()
                .process()
                .unwrap()
                .get_dirty_pages(PageFlag::SoftDirty, extra_writable_ranges)?,
        };

        Ok(DirtyPageAddressesWithFlags {
            addresses: Box::new(pages),
            flags: DirtyPageAddressFlags {
                contains_writable_only: true,
            },
        })
    }
}

impl SegmentEventHandler for SoftDirtyPageTracker {
    fn handle_checkpoint_created_pre(&self, main: &mut Main<Stopped>) -> Result<()> {
        if !self.dont_clear_soft_dirty {
            main.process_mut().clear_dirty_page_bits()?;
        }

        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker<Stopped>) -> Result<()> {
        if !self.dont_clear_soft_dirty {
            checker.process_mut().clear_dirty_page_bits()?;
        }

        Ok(())
    }
}

impl Module for SoftDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
        subs.install_segment_event_handler(self);
    }
}
