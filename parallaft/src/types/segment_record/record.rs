use std::sync::Arc;

use parking_lot::{Condvar, Mutex};

use super::{saved_event::SavedEvent, saved_syscall::SavedIncompleteSyscall};

use crate::error::Result;

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
pub enum MainStatus {
    #[default]
    Filling,
    Completed,
    Crashed,
}

#[derive(Debug, Default)]
pub struct State {
    pub main_status: MainStatus,
    pub event_log: Vec<SavedEvent>,
    pub last_incomplete_syscall: Option<SavedIncompleteSyscall>,
}

#[derive(Debug)]
pub struct SegmentRecord {
    pub state: Mutex<State>,
    pub cvar: Condvar,

    /// Enable active events, including execution points and external signals.
    /// When this is enabled, checkers will stop execution until there are at
    /// least one upcoming events to replay (to ensure checkers will never go
    /// past possibly upcoming active events).
    pub with_active_events: bool,
}

impl SegmentRecord {
    pub fn new(with_active_events: bool) -> Self {
        Self {
            state: Mutex::new(State::default()),
            cvar: Condvar::new(),
            with_active_events,
        }
    }

    pub fn mark_main_as_crashed(&self) {
        let mut state = self.state.lock();
        state.main_status = MainStatus::Crashed;
        self.cvar.notify_all();
    }

    pub fn push_incomplete_syscall(&self, incomplete_syscall: SavedIncompleteSyscall) {
        let mut state = self.state.lock();
        assert!(state.last_incomplete_syscall.is_none());
        state.last_incomplete_syscall = Some(incomplete_syscall);
        self.cvar.notify_all();
    }

    pub fn take_incomplete_syscall(&self) -> Option<SavedIncompleteSyscall> {
        let mut state = self.state.lock();
        state.last_incomplete_syscall.take()
    }

    pub fn get_last_incomplete_syscall(&self) -> Option<Arc<SavedIncompleteSyscall>> {
        self.state
            .lock()
            .event_log
            .last()
            .and_then(|event| event.get_incomplete_syscall().ok())
    }

    pub fn push_event(&self, event: impl Into<SavedEvent>, is_last: bool) -> Result<()> {
        let event: SavedEvent = event.into();

        let mut state = self.state.lock();
        assert_eq!(state.main_status, MainStatus::Filling);

        if is_last {
            if let Some(incomplete_syscall) = state.last_incomplete_syscall.take() {
                state
                    .event_log
                    .push(SavedEvent::IncompleteSyscall(Arc::new(incomplete_syscall)));
            }

            state.main_status = MainStatus::Completed;
        }

        state.event_log.push(event);

        self.cvar.notify_all();

        Ok(())
    }
}
