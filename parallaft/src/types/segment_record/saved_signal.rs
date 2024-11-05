use std::sync::Arc;

use nix::libc::siginfo_t;

use crate::{
    error::{Error, Result, UnexpectedEventReason},
    types::execution_point::ExecutionPoint,
};

use super::saved_event::SavedEventType;

#[derive(Debug, Clone)]
pub enum SavedSignal {
    Internal(siginfo_t),
    External(siginfo_t, Arc<dyn ExecutionPoint>),
}

impl SavedSignal {
    pub fn get_internal_signal(&self) -> Result<siginfo_t> {
        match self {
            Self::Internal(siginfo) => Ok(*siginfo),
            _ => Err(Error::UnexpectedEvent(
                UnexpectedEventReason::IncorrectType {
                    expected: SavedEventType::InternalSignal,
                    got: self.clone().into(),
                },
            )),
        }
    }
}
