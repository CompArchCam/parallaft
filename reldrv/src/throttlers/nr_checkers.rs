use std::{collections::HashSet, sync::Arc};

use log::debug;
use parking_lot::{Condvar, Mutex};

use crate::{
    dispatcher::Module,
    error::Result,
    events::{migration::MigrationHandler, segment::SegmentEventHandler, HandlerContext},
    process::state::{Running, Stopped},
    types::{
        checker::CheckFailReason,
        process_id::{Checker, Main},
        segment::{Segment, SegmentId},
    },
};

pub struct NrCheckersBasedThrottler<'a> {
    checker_cpu_set: &'a [usize],
    live_checkers: Mutex<HashSet<SegmentId>>,
    cvar: Condvar,
}

impl<'a> NrCheckersBasedThrottler<'a> {
    pub fn new(checker_cpu_set: &'a [usize]) -> Self {
        Self {
            checker_cpu_set,
            live_checkers: Mutex::new(HashSet::with_capacity(checker_cpu_set.len())),
            cvar: Condvar::new(),
        }
    }
}

impl SegmentEventHandler for NrCheckersBasedThrottler<'_> {
    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        let mut live_checkers = self.live_checkers.lock();
        live_checkers.insert(main.segment.as_ref().unwrap().nr);
        Ok(())
    }

    fn handle_segment_ready(&self, checker: &mut Checker<Stopped>) -> crate::error::Result<()> {
        let mut live_checkers = self.live_checkers.lock();

        let mut printed = false;

        while live_checkers
            .iter()
            .filter(|&&x| {
                x < checker.segment.nr
                    && checker.segment.checker_status.lock().cpu_set().unwrap()
                        == self.checker_cpu_set
            })
            .count()
            >= self.checker_cpu_set.len()
        {
            if !printed {
                debug!("{} Throttling due to too many checkers running", checker);
                printed = true;
            }

            self.cvar.wait(&mut live_checkers);
        }

        Ok(())
    }

    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
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

impl MigrationHandler for NrCheckersBasedThrottler<'_> {
    fn handle_checker_migration(&self, _ctx: HandlerContext<Stopped>) -> Result<()> {
        self.cvar.notify_all();
        Ok(())
    }
}

impl Module for NrCheckersBasedThrottler<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_migration_handler(self);
    }
}
