use libfpt_rs::{FptFd, FptFlags, FptRecord};
use parking_lot::Mutex;
use std::{collections::HashMap, sync::Arc};

use crate::{
    dirty_page_trackers::DirtyPageAddressFlags,
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    events::segment::SegmentEventHandler,
    process::state::Stopped,
    types::{
        process_id::{Checker, InferiorId, Main},
        segment::{Segment, SegmentId},
    },
};

use super::{DirtyPageAddressTracker, DirtyPageAddressesWithFlags};

const FPT_BUFFER_SIZE: usize = 2 * 1024 * 1024; // 2M entries (16MB buffer)
const FPT_FLAGS: FptFlags = FptFlags::ALLOW_REALLOC;

pub struct FptDirtyPageTracker {
    fd_main: Mutex<Option<FptFd>>,
    fd_map: Mutex<HashMap<SegmentId, FptFd>>,
    record_map: Mutex<HashMap<InferiorId, FptRecord>>,
}

impl Default for FptDirtyPageTracker {
    fn default() -> Self {
        Self::new()
    }
}

impl FptDirtyPageTracker {
    pub fn new() -> Self {
        Self {
            fd_main: Mutex::new(None),
            fd_map: Mutex::new(HashMap::new()),
            record_map: Mutex::new(HashMap::new()),
        }
    }
}

impl DirtyPageAddressTracker for FptDirtyPageTracker {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: InferiorId,
        _extra_writable_ranges: &[std::ops::Range<usize>],
    ) -> Result<DirtyPageAddressesWithFlags> {
        let mut record_map = self.record_map.lock();

        let record = record_map.remove(&inferior_id).ok_or(Error::InvalidState)?;

        Ok(DirtyPageAddressesWithFlags {
            addresses: Box::new(record),
            flags: DirtyPageAddressFlags::default(),
        })
    }

    fn nr_dirty_pages(&self, inferior_id: InferiorId) -> Result<usize> {
        Ok(match inferior_id {
            InferiorId::Main(_) => {
                let fd = self.fd_main.lock();
                fd.as_ref().map_or(Ok(0), |fd| fd.get_count())?
            }
            InferiorId::Checker(segment) => {
                let fd_map = self.fd_map.lock();
                fd_map.get(&segment.nr).unwrap().get_count()?
            }
        })
    }
}

impl SegmentEventHandler for FptDirtyPageTracker {
    fn handle_checkpoint_created_pre(&self, main: &mut Main<Stopped>) -> Result<()> {
        let mut fd = self.fd_main.lock();
        let fd_mut = fd.get_or_insert_with(|| {
            let mut fd_inner = FptFd::new(main.process().pid, FPT_BUFFER_SIZE, FPT_FLAGS, None)
                .expect("Failed to initialise FPT dirty page tracker");
            fd_inner.enable().unwrap();
            fd_inner
        });

        if let Some(last_segment) = &main.segment {
            let record = fd_mut.take_record()?;
            let mut record_map = self.record_map.lock();

            record_map.insert(InferiorId::Main(Some(last_segment.clone())), record);
        }

        fd_mut.clear_fault()?;

        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker<Stopped>) -> Result<()> {
        let mut fd = FptFd::new(checker.process().pid, FPT_BUFFER_SIZE, FPT_FLAGS, None)
            .expect("FPT: failed to initialise FPT dirty page tracker");

        fd.enable()?;

        let mut fd_map = self.fd_map.lock();
        fd_map.insert(checker.segment.nr, fd);

        Ok(())
    }

    fn handle_segment_completed(&self, checker: &mut Checker<Stopped>) -> Result<()> {
        let mut fd_map = self.fd_map.lock();

        let mut fd = fd_map
            .remove(&checker.segment.nr)
            .expect("FPT: segment number doesn't exist in fd_map");

        drop(fd_map);

        fd.disable()?;

        let record = fd.take_record()?;
        drop(fd);

        let mut record_map = self.record_map.lock();
        record_map.insert(checker.into(), record);

        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        let mut fd_map = self.fd_map.lock();
        fd_map.remove(&segment.nr);

        let mut record_map = self.record_map.lock();
        record_map.remove(&InferiorId::Main(Some(segment.clone())));
        record_map.remove(&InferiorId::Checker(segment.clone()));

        Ok(())
    }
}

impl Module for FptDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
        subs.install_segment_event_handler(self);
    }
}
