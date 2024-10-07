use std::{
    hash::{Hash, Hasher},
    sync::Arc,
};

use parking_lot::Mutex;

use super::{
    checker_status::CheckerStatus,
    segment::Segment,
    segment_record::{record::SegmentRecord, replay::SegmentReplay},
};

use crate::{
    error::Result,
    process::{state::Stopped, Process},
};

pub type CheckerExecutionId = u32;

#[derive(Debug)]
pub struct CheckerExecution {
    pub id: CheckerExecutionId,
    pub status: Mutex<CheckerStatus>,
    pub replay: SegmentReplay,
}

impl CheckerExecution {
    pub fn new(id: CheckerExecutionId, record: Arc<SegmentRecord>) -> Self {
        Self {
            id,
            status: Mutex::new(CheckerStatus::NotReady),
            replay: SegmentReplay::new(record),
        }
    }

    pub fn start_checker(
        &self,
        checker_cpu_set: Vec<usize>,
        segment: &Segment,
    ) -> Result<Process<Stopped>> {
        self.replay.rewind()?;
        let mut status = self.status.lock();
        assert!(!matches!(&*status, CheckerStatus::Executing { .. }));
        status.start(&segment.checkpoint_start, checker_cpu_set)
    }

    pub fn is_finished(&self) -> bool {
        self.status.lock().is_finished()
    }
}

impl PartialEq for CheckerExecution {
    fn eq(&self, other: &Self) -> bool {
        self.id == other.id
    }
}

impl Eq for CheckerExecution {}

impl Hash for CheckerExecution {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.id.hash(state);
    }
}
