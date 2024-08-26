use std::{fmt::Debug, sync::Arc};

use log::debug;
use parking_lot::Mutex;

use crate::{
    error::Result,
    types::{
        execution_point::ExecutionPoint, perf_counter::symbolic_events::BranchType,
        segment::Segment,
    },
};

use super::{PerfCounterBasedExecutionPointProvider, SegmentInfo};

#[derive(Clone)]
pub struct BranchCounterBasedExecutionPoint {
    pub branch_count: u64,
    pub instruction_pointer: usize,
    pub ty: BranchType,
    pub segment_info: Arc<Mutex<SegmentInfo>>,
}

impl PartialEq for BranchCounterBasedExecutionPoint {
    fn eq(&self, other: &Self) -> bool {
        self.branch_count == other.branch_count
            && self.instruction_pointer == other.instruction_pointer
            && self.ty == other.ty
    }
}

impl Eq for BranchCounterBasedExecutionPoint {}

impl Debug for BranchCounterBasedExecutionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("BranchCounterBasedExecutionPoint")
            .field("branch_counter", &self.branch_count)
            .field("instruction_pointer", &self.instruction_pointer)
            .field("ty", &self.ty)
            .finish()
    }
}

impl ExecutionPoint for BranchCounterBasedExecutionPoint {
    fn prepare(&self, segment: &Segment) -> Result<()> {
        debug!("Preparing execution point {self:?}");
        let mut segment_info = self.segment_info.lock();

        segment_info.upcoming_exec_points.push_back(self.clone());

        if segment_info.active_exec_point.is_none() {
            if let Some(process) = segment.checker_status.lock().process() {
                process.sigqueue(
                    PerfCounterBasedExecutionPointProvider::SIGVAL_CHECKER_PREPARE_EXEC_POINT,
                )?;
            }
        }

        Ok(())
    }
}
