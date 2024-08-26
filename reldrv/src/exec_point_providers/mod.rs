pub mod pmu;

use std::sync::Arc;

use crate::{
    error::Result,
    process::state::Stopped,
    types::{execution_point::ExecutionPoint, process_id::InferiorRefMut},
};

pub trait ExecutionPointProvider: Sync {
    fn get_current_execution_point(
        &self,
        child: &mut InferiorRefMut<Stopped>,
    ) -> Result<Arc<dyn ExecutionPoint>>;
}
