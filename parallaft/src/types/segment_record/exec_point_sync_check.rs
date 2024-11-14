use std::sync::Arc;

use crate::types::execution_point::ExecutionPoint;

#[derive(Debug, Clone)]
pub struct ExecutionPointSyncCheck(pub Arc<dyn ExecutionPoint>);
