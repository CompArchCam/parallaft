use libfpt_rs::{FptFd, FptFlags, FptRecord};
use nix::unistd::Pid;
use parking_lot::Mutex;
use std::collections::HashMap;

use crate::{
    check_coord::ProcessRole,
    dirty_page_trackers::DirtyPageAddressFlags,
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    types::segment::{Segment, SegmentEventHandler, SegmentId},
};

use super::{DirtyPageAddressTracker, DirtyPageAddressTrackerContext};

const FPT_BUFFER_SIZE: usize = 2 * 1024 * 1024; // 2M entries (16MB buffer)
const FPT_FLAGS: FptFlags = FptFlags::ALLOW_REALLOC;
const MSG_FPT_INIT_FAILED: &'static str = "Failed to initialise FPT dirty page tracker";

pub struct FptDirtyPageTracker {
    fd_main: Mutex<Option<FptFd>>,
    fd_map: Mutex<HashMap<SegmentId, FptFd>>,
    record_map: Mutex<HashMap<(SegmentId, ProcessRole), FptRecord>>,
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
    fn take_dirty_pages_addresses<'a>(
        &self,
        segment_id: SegmentId,
        role: ProcessRole,
        _ctx: &DirtyPageAddressTrackerContext<'a>,
    ) -> Result<(Box<dyn AsRef<[usize]>>, DirtyPageAddressFlags)> {
        let mut record_map = self.record_map.lock();

        let record = record_map
            .remove(&(segment_id, role))
            .ok_or(Error::InvalidState)?;

        Ok((Box::new(record), DirtyPageAddressFlags::default()))
    }

    fn nr_dirty_pages<'a>(
        &self,
        role: ProcessRole,
        ctx: &DirtyPageAddressTrackerContext<'a>,
    ) -> Result<usize> {
        Ok(match role {
            ProcessRole::Main => {
                let fd = self.fd_main.lock();
                fd.as_ref().map_or(Ok(0), |fd| fd.get_count())?
            }
            ProcessRole::Checker => {
                let fd_map = self.fd_map.lock();
                fd_map.get(&ctx.segment.nr).unwrap().get_count()?
            }
        })
    }
}

impl SegmentEventHandler for FptDirtyPageTracker {
    fn handle_checkpoint_created_pre(
        &self,
        main_pid: Pid,
        last_segment_id: Option<SegmentId>,
    ) -> Result<()> {
        let mut fd = self.fd_main.lock();
        let fd_mut = fd.get_or_insert_with(|| {
            let mut fd_inner =
                FptFd::new(main_pid, FPT_BUFFER_SIZE, FPT_FLAGS, None).expect(MSG_FPT_INIT_FAILED);
            fd_inner.enable().unwrap();
            fd_inner
        });

        if let Some(last_segment_id) = last_segment_id {
            let record = fd_mut.take_record()?;
            let mut record_map = self.record_map.lock();

            record_map.insert((last_segment_id, ProcessRole::Main), record);
        }

        fd_mut.clear_fault()?;

        Ok(())
    }

    fn handle_segment_created(&self, segment: &Segment) -> Result<()> {
        let checker = segment.checker.process().unwrap();
        let mut fd =
            FptFd::new(checker.pid, FPT_BUFFER_SIZE, FPT_FLAGS, None).expect(MSG_FPT_INIT_FAILED);

        fd.enable()?;

        let mut fd_map = self.fd_map.lock();
        fd_map.insert(segment.nr, fd);

        Ok(())
    }

    fn handle_segment_ready(&self, segment: &mut Segment) -> Result<()> {
        let mut fd_map = self.fd_map.lock();

        let mut fd = fd_map
            .remove(&segment.nr)
            .expect("fpt: segment number doesn't exist in fd_map");

        drop(fd_map);

        fd.disable()?;

        let record = fd.take_record()?;
        drop(fd);

        let mut record_map = self.record_map.lock();
        record_map.insert((segment.nr, ProcessRole::Checker), record);

        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Segment) -> Result<()> {
        let mut fd_map = self.fd_map.lock();
        fd_map.remove(&segment.nr);

        let mut record_map = self.record_map.lock();
        record_map.remove(&(segment.nr, ProcessRole::Main));
        record_map.remove(&(segment.nr, ProcessRole::Checker));

        Ok(())
    }
}

impl Module for FptDirtyPageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_dirty_page_tracker(self);
        subs.install_segment_event_handler(self);
    }
}
