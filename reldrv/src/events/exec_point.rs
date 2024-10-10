use crate::{
    error::Result,
    process::state::Stopped,
    types::{execution_point::ExecutionPoint, process_id::Checker},
};

pub trait ExecutionPointEventHandler: Sync {
    fn handle_freestanding_exec_point_reached(
        &self,
        exec_point: &dyn ExecutionPoint,
        checker: &mut Checker<Stopped>,
    ) -> Result<()>;
}
