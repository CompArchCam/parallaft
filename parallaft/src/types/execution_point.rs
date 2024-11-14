use std::fmt::{Debug, Display};

use dyn_eq::DynEq;

use super::{checker_exec::CheckerExecution, segment::Segment};

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ExecutionPointOwner {
    SegmentRecord,
    Freestanding,
}

pub trait ExecutionPoint: DynEq + Debug + Send + Sync + Display {
    fn prepare(
        &self,
        segment: &Segment,
        exec: &CheckerExecution,
        owner: ExecutionPointOwner,
    ) -> Result<()>;
}

dyn_eq::eq_trait_object!(ExecutionPoint);
