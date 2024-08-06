use std::{collections::HashSet, sync::Arc};

use parking_lot::{Condvar, Mutex};

use crate::{
    dispatcher::Module,
    error::Result,
    events::segment::SegmentEventHandler,
    types::{
        checker::CheckFailReason,
        process_id::{Checker, Main},
        segment::{Segment, SegmentId},
    },
};

pub struct NrCheckersBasedThrottler {
    max_nr_live_checkers: usize,
    live_checkers: Mutex<HashSet<SegmentId>>,
    cvar: Condvar,
}

impl NrCheckersBasedThrottler {
    pub fn new(max_nr_live_checkers: usize) -> Self {
        Self {
            max_nr_live_checkers,
            live_checkers: Mutex::new(HashSet::with_capacity(max_nr_live_checkers)),
            cvar: Condvar::new(),
        }
    }
}

impl SegmentEventHandler for NrCheckersBasedThrottler {
    fn handle_segment_created(&self, main: &mut Main) -> Result<()> {
        let mut live_checkers = self.live_checkers.lock();
        live_checkers.insert(main.segment.as_ref().unwrap().nr);
        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker) -> crate::error::Result<()> {
        let mut live_checkers = self.live_checkers.lock();

        while live_checkers
            .iter()
            .filter(|&&x| x < checker.segment.nr)
            .count()
            >= self.max_nr_live_checkers
        {
            self.cvar.wait(&mut live_checkers);
        }

        Ok(())
    }

    fn handle_segment_checked(
        &self,
        checker: &mut Checker,
        _check_fail_reason: &Option<CheckFailReason>,
    ) -> Result<()> {
        self.live_checkers.lock().remove(&checker.segment.nr);
        self.cvar.notify_all();
        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        self.live_checkers.lock().remove(&segment.nr);
        self.cvar.notify_all();
        Ok(())
    }
}

impl Module for NrCheckersBasedThrottler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
    }
}
