use log::debug;

use crate::{
    dispatcher::Module,
    error::Result,
    events::segment::SegmentEventHandler,
    process::{dirty_pages::AsIoSlice, PAGESIZE},
    types::process_id::Main,
};

pub struct Madviser;

impl Madviser {
    pub fn new() -> Self {
        Self
    }
}

impl SegmentEventHandler for Madviser {
    fn handle_segment_created(&self, main: &mut Main) -> Result<()> {
        let segment = main.segment.as_ref().unwrap().clone();

        // TODO: take dirty page addresses if necessary

        let process = segment.checkpoint_start.process.lock();
        let mut iovecs = Vec::new();

        process.for_each_writable_map(
            |map| {
                iovecs.push(map.as_io_slice());
                Ok(())
            },
            &[],
        )?;

        let advised = process.madvise(&iovecs, nix::libc::MADV_COLD)?;

        debug!("{main} Advised {} pages to MADV_COLD", advised / *PAGESIZE);

        Ok(())
    }
}

impl Module for Madviser {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
    }
}
