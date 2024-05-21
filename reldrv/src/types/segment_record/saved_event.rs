use std::sync::Arc;

use crate::types::execution_point::ExecutionPoint;

use super::{
    manual_checkpoint::ManualCheckpointRequest,
    saved_signal::SavedSignal,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    saved_trap_event::SavedTrapEvent,
};

#[derive(Debug, Clone)]
pub enum SavedEvent {
    Syscall(Arc<SavedSyscall>),
    IncompleteSyscall(Arc<SavedIncompleteSyscall>),
    TrapEvent(Arc<SavedTrapEvent>),
    Signal(Arc<SavedSignal>),
    ExecutionPoint(Arc<dyn ExecutionPoint>),
    ManualCheckpointRequest(ManualCheckpointRequest),
}

impl From<SavedSyscall> for SavedEvent {
    fn from(syscall: SavedSyscall) -> Self {
        SavedEvent::Syscall(Arc::new(syscall))
    }
}

impl From<SavedIncompleteSyscall> for SavedEvent {
    fn from(incomplete_syscall: SavedIncompleteSyscall) -> Self {
        SavedEvent::IncompleteSyscall(Arc::new(incomplete_syscall))
    }
}

impl From<SavedTrapEvent> for SavedEvent {
    fn from(trap_event: SavedTrapEvent) -> Self {
        SavedEvent::TrapEvent(Arc::new(trap_event))
    }
}

impl From<SavedSignal> for SavedEvent {
    fn from(signal: SavedSignal) -> Self {
        SavedEvent::Signal(Arc::new(signal))
    }
}

impl From<Arc<dyn ExecutionPoint>> for SavedEvent {
    fn from(execution_point: Arc<dyn ExecutionPoint>) -> Self {
        SavedEvent::ExecutionPoint(execution_point)
    }
}

impl From<ManualCheckpointRequest> for SavedEvent {
    fn from(manual_checkpoint_request: ManualCheckpointRequest) -> Self {
        SavedEvent::ManualCheckpointRequest(manual_checkpoint_request)
    }
}

impl SavedEvent {
    pub fn get_syscall(&self) -> Option<Arc<SavedSyscall>> {
        match self {
            SavedEvent::Syscall(syscall) => Some(syscall.clone()),
            _ => None,
        }
    }

    pub fn get_incomplete_syscall(&self) -> Option<Arc<SavedIncompleteSyscall>> {
        match self {
            SavedEvent::IncompleteSyscall(incomplete_syscall) => Some(incomplete_syscall.clone()),
            _ => None,
        }
    }

    pub fn get_trap_event(&self) -> Option<Arc<SavedTrapEvent>> {
        match self {
            SavedEvent::TrapEvent(trap_event) => Some(trap_event.clone()),
            _ => None,
        }
    }

    pub fn get_signal(&self) -> Option<Arc<SavedSignal>> {
        match self {
            SavedEvent::Signal(signal) => Some(signal.clone()),
            _ => None,
        }
    }

    pub fn get_execution_point(&self) -> Option<Arc<dyn ExecutionPoint>> {
        match self {
            SavedEvent::ExecutionPoint(execution_point) => Some(execution_point.clone()),
            _ => None,
        }
    }

    pub fn get_manual_checkpoint_request(&self) -> Option<ManualCheckpointRequest> {
        match self {
            SavedEvent::ManualCheckpointRequest(manual_checkpoint_request) => {
                Some(*manual_checkpoint_request)
            }
            _ => None,
        }
    }
}
