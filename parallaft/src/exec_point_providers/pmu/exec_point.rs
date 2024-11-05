use std::{collections::HashMap, fmt::Display, sync::Arc};

use derivative::Derivative;
use log::debug;
use parking_lot::Mutex;

use crate::{
    error::Result,
    types::{
        checker_exec::{CheckerExecution, CheckerExecutionId},
        execution_point::{ExecutionPoint, ExecutionPointOwner},
        perf_counter::symbolic_events::BranchType,
        segment::{Segment, SegmentId},
    },
};

use super::{ExecInfo, PerfCounterBasedExecutionPointProvider};

#[derive(Clone, Derivative)]
#[derivative(Debug)]
pub struct BranchCounterBasedExecutionPoint {
    pub branch_count: u64,
    pub instruction_pointer: usize,
    pub ty: BranchType,
    #[derivative(Debug = "ignore")]
    pub exec_info_map:
        Arc<Mutex<HashMap<SegmentId, HashMap<CheckerExecutionId, Arc<Mutex<ExecInfo>>>>>>,
}

impl Display for BranchCounterBasedExecutionPoint {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "{} branches @ {:#0x}",
            self.branch_count, self.instruction_pointer
        )
    }
}

impl PartialEq for BranchCounterBasedExecutionPoint {
    fn eq(&self, other: &Self) -> bool {
        self.branch_count == other.branch_count
            && self.instruction_pointer == other.instruction_pointer
            && self.ty == other.ty
    }
}

impl Eq for BranchCounterBasedExecutionPoint {}

impl PartialOrd for BranchCounterBasedExecutionPoint {
    fn partial_cmp(&self, other: &Self) -> Option<std::cmp::Ordering> {
        Some(self.cmp(other))
    }
}

impl Ord for BranchCounterBasedExecutionPoint {
    fn cmp(&self, other: &Self) -> std::cmp::Ordering {
        (self.branch_count, self.instruction_pointer)
            .cmp(&(other.branch_count, other.instruction_pointer))
    }
}

impl ExecutionPoint for BranchCounterBasedExecutionPoint {
    fn prepare(
        &self,
        segment: &Segment,
        exec: &CheckerExecution,
        owner: ExecutionPointOwner,
    ) -> Result<()> {
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
        exec_info.add_exec_point_to_queue(self.clone(), owner)?;

        if let Some(process) = exec.status.lock().process() {
            process.sigqueue(
                PerfCounterBasedExecutionPointProvider::SIGVAL_CHECKER_PREPARE_EXEC_POINT,
            )?;
        }

        Ok(())
    }
}
