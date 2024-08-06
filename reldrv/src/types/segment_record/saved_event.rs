use std::sync::Arc;

use crate::{
    error::{Error, Result, UnexpectedEventReason},
    types::execution_point::ExecutionPoint,
};

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

#[derive(Debug, Copy, Clone, Eq, PartialEq)]
pub enum SavedEventType {
    Syscall,
    IncompleteSyscall,
    TrapEvent,
    Signal,
    ExecutionPoint,
    ManualCheckpointRequest,
}

impl From<&SavedEvent> for SavedEventType {
    fn from(event: &SavedEvent) -> Self {
        match event {
            SavedEvent::Syscall(_) => SavedEventType::Syscall,
            SavedEvent::IncompleteSyscall(_) => SavedEventType::IncompleteSyscall,
            SavedEvent::TrapEvent(_) => SavedEventType::TrapEvent,
            SavedEvent::Signal(_) => SavedEventType::Signal,
            SavedEvent::ExecutionPoint(_) => SavedEventType::ExecutionPoint,
            SavedEvent::ManualCheckpointRequest(_) => SavedEventType::ManualCheckpointRequest,
        }
    }
}

macro_rules! impl_getter {
    ($name:ident, $variant:ident, $return_type:ty) => {
        pub fn $name(&self) -> Result<$return_type> {
            match self {
                SavedEvent::$variant(value) => Ok(value.clone()),
                _ => Err(Error::UnexpectedEvent(
                    UnexpectedEventReason::IncorrectType {
                        expected: SavedEventType::$variant,
                        got: self.clone(),
                    },
                )),
            }
        }
    };
    () => {};
}

impl SavedEvent {
    impl_getter!(get_syscall, Syscall, Arc<SavedSyscall>);
    impl_getter!(
        get_incomplete_syscall,
        IncompleteSyscall,
        Arc<SavedIncompleteSyscall>
    );
    impl_getter!(get_trap_event, TrapEvent, Arc<SavedTrapEvent>);
    impl_getter!(get_signal, Signal, Arc<SavedSignal>);
    impl_getter!(get_execution_point, ExecutionPoint, Arc<dyn ExecutionPoint>);
    impl_getter!(
        get_manual_checkpoint_request,
        ManualCheckpointRequest,
        ManualCheckpointRequest
    );
}
