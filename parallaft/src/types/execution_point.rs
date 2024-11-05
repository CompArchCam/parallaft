use std::{
    any::Any,
    fmt::{Debug, Display},
};

use super::{checker_exec::CheckerExecution, segment::Segment};

use crate::error::Result;

pub trait DynEq {
    fn as_any(&self) -> &dyn Any;
    fn do_eq(&self, rhs: &dyn DynEq) -> bool;
}

impl<T> DynEq for T
where
    T: PartialEq + 'static,
{
    fn as_any(&self) -> &dyn Any {
        self
    }

    fn do_eq(&self, rhs: &dyn DynEq) -> bool {
        if let Some(rhs_concrete) = rhs.as_any().downcast_ref::<Self>() {
            self == rhs_concrete
        } else {
            false
        }
    }
}

impl PartialEq for dyn DynEq {
    fn eq(&self, rhs: &Self) -> bool {
        self.do_eq(rhs)
    }
}

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
