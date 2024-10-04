use std::{collections::HashMap, fmt::Debug, sync::Arc};

use log::debug;
use parking_lot::Mutex;

use crate::{
    error::Result,
    types::{
        checker_exec::{CheckerExecution, CheckerExecutionId},
        execution_point::ExecutionPoint,
        perf_counter::symbolic_events::BranchType,
        segment::{Segment, SegmentId},
    },
};

use super::{ExecInfo, PerfCounterBasedExecutionPointProvider};

#[derive(Clone, Debug)]
pub struct BranchCounterBasedExecutionPoint {
    pub branch_count: u64,
    pub instruction_pointer: usize,
    pub ty: BranchType,
    pub exec_info_map:
        Arc<Mutex<HashMap<SegmentId, HashMap<CheckerExecutionId, Arc<Mutex<ExecInfo>>>>>>,
}

impl PartialEq for BranchCounterBasedExecutionPoint {
    fn eq(&self, other: &Self) -> bool {
        self.branch_count == other.branch_count
            && self.instruction_pointer == other.instruction_pointer
            && self.ty == other.ty
    }
}

impl Eq for BranchCounterBasedExecutionPoint {}

impl ExecutionPoint for BranchCounterBasedExecutionPoint {
    fn prepare(&self, segment: &Segment, exec: &CheckerExecution) -> Result<()> {
        debug!("Preparing execution point {self:?}");
        let exec_info_map = self.exec_info_map.lock();

        let exec_info = exec_info_map
            .get(&segment.nr)
            .unwrap()
            .get(&exec.id)
            .unwrap()
            .clone();

        drop(exec_info_map);

        let mut exec_info = exec_info.lock();
        exec_info.upcoming_exec_points.push_back(self.clone());

        if exec_info.active_exec_point.is_none() {
            if let Some(process) = exec.status.lock().process() {
                process.sigqueue(
                    PerfCounterBasedExecutionPointProvider::SIGVAL_CHECKER_PREPARE_EXEC_POINT,
                )?;
            }
        }

        Ok(())
    }
}
