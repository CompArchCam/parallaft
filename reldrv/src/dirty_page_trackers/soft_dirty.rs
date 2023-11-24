use nix::unistd::Pid;

use crate::{
    check_coord::ProcessRole,
    dispatcher::{Dispatcher, Installable},
    error::Result,
    process::Process,
    segments::{Segment, SegmentEventHandler, SegmentId},
};

use super::{DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressTrackerContext};

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
    fn take_dirty_pages_addresses<'a>(
        &self,
        _segment_id: SegmentId,
        role: ProcessRole,
        ctx: &DirtyPageAddressTrackerContext<'a>,
    ) -> Result<(Box<dyn AsRef<[usize]>>, DirtyPageAddressFlags)> {
        match role {
            ProcessRole::Main => {
                let pages = ctx.segment.reference_end().unwrap().get_dirty_pages()?;
                Ok((Box::new(pages), DirtyPageAddressFlags::CONTAINS_WR_ONLY))
            }
            ProcessRole::Checker => {
                let pages = ctx.segment.checker().unwrap().get_dirty_pages()?;
                Ok((Box::new(pages), DirtyPageAddressFlags::CONTAINS_WR_ONLY))
            }
        }
    }
}

impl SegmentEventHandler for SoftDirtyPageTracker {
    fn handle_checkpoint_created_pre(
        &self,
        main_pid: Pid,
        _last_segment_id: Option<SegmentId>,
    ) -> Result<()> {
        if !self.dont_clear_soft_dirty {
            Process::new(main_pid).clear_dirty_page_bits()?;
        }

        Ok(())
    }

    fn handle_segment_created(&self, segment: &Segment) -> Result<()> {
        if !self.dont_clear_soft_dirty {
            segment.checker().unwrap().clear_dirty_page_bits()?;
        }

        Ok(())
    }
}

impl<'a> Installable<'a> for SoftDirtyPageTracker {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_dirty_page_tracker(self);
        dispatcher.install_segment_event_handler(self);
    }
}
