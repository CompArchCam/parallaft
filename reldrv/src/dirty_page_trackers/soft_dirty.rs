use crate::{
    dispatcher::Module,
    error::Result,
    events::segment::SegmentEventHandler,
    process::Process,
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
    ) -> Result<DirtyPageAddressesWithFlags> {
        let pages = match &inferior_id {
            InferiorId::Main(segment) => segment
                .as_ref()
                .unwrap()
                .checkpoint_end()
                .unwrap()
                .process
                .lock()
                .get_dirty_pages()?,
            InferiorId::Checker(segment) => {
                let pid = segment.checker_status.lock().pid().unwrap();
                Process::new(pid).get_dirty_pages()?
            }
        };

        Ok(DirtyPageAddressesWithFlags {
            addresses: Box::new(pages),
            flags: DirtyPageAddressFlags {
                contains_writable_only: true,
            },
        })
    }

    fn nr_dirty_pages(&self, inferior_id: InferiorId) -> Result<usize> {
        let pid = match inferior_id {
            InferiorId::Main(segment) => segment.unwrap().status.lock().pid().unwrap(),
            InferiorId::Checker(segment) => segment.checker_status.lock().pid().unwrap(),
        };

        Ok(Process::new(pid).memory_stats()?.dirty_pages)
    }
}

impl SegmentEventHandler for SoftDirtyPageTracker {
    fn handle_checkpoint_created_pre(&self, main: &mut Main) -> Result<()> {
        if !self.dont_clear_soft_dirty {
            main.process.clear_dirty_page_bits()?;
        }

        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker) -> Result<()> {
        if !self.dont_clear_soft_dirty {
            checker.process.clear_dirty_page_bits()?;
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
