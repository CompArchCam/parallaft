pub mod manual_checkpoint;
pub mod saved_event;
pub mod saved_memory;
pub mod saved_signal;
pub mod saved_syscall;
pub mod saved_trap_event;

use std::sync::Arc;

use manual_checkpoint::ManualCheckpointRequest;
use parking_lot::{Condvar, Mutex, MutexGuard};

use self::{
    saved_event::SavedEvent,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    saved_trap_event::SavedTrapEvent,
};

use crate::{
    error::{Error, Result, UnexpectedEventReason},
    events::signal::SignalHandlerExitAction,
};

use super::{execution_point::ExecutionPoint, segment::Segment};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default)]
enum MainStatus {
    #[default]
    Filling,
    Completed,
    Crashed,
}

pub type EventPos = usize;

#[derive(Debug, Default)]
struct State {
    event_pos: EventPos,
    main_status: MainStatus,
    event_log: Vec<SavedEvent>,
    last_incomplete_syscall: Option<SavedIncompleteSyscall>,
    is_waiting: bool,
}

#[derive(Debug)]
pub struct SegmentRecord {
    state: Mutex<State>,
    cvar: Condvar,

    /// Enable async events support, including execution points and external
    /// signals. When this is enabled, checkers will stop execution until there
    /// are at least one upcoming events to replay (to ensure checkers will
    /// never go past possibly upcoming async events).
    pub enable_async_events: bool,
}

#[derive(Debug)]
pub struct WithIsLastEvent<T> {
    pub is_last_event: bool,
    pub value: T,
}

impl<T> WithIsLastEvent<T> {
    pub fn new(is_last_event: bool, value: T) -> Self {
        Self {
            is_last_event,
            value,
        }
    }

    pub fn signal_handler_exit_action(&self) -> SignalHandlerExitAction {
        if self.is_last_event {
            SignalHandlerExitAction::Checkpoint
        } else {
            SignalHandlerExitAction::SuppressSignalAndContinueInferior
        }
    }
}

impl SegmentRecord {
    pub fn new(enable_async_events: bool) -> Self {
        Self {
            state: Mutex::new(State::default()),
            cvar: Condvar::new(),
            enable_async_events,
        }
    }

    pub fn is_waiting(&self) -> bool {
        self.state.lock().is_waiting
    }

    /// Wait until there are at least two uncomping events to replay, so that
    /// checkers will never go past possibly-upcoming async events, if
    /// `self.enable_async_events_support` is true. Otherwise, wait until one
    /// event is available.
    fn wait_until_event_available(&self) -> Result<MutexGuard<State>> {
        if !self.enable_async_events {
            self.wait_until_n_events_available(1)
        } else {
            self.wait_until_n_events_available(2)
        }
    }

    /// Rewind the checker pos to the beginning of the segment, cancelling
    /// existing checkers' execution.
    pub fn rewind(&self, segment: &Segment) -> Result<()> {
        let mut state = self.state.lock();
        state.event_pos = 0;
        for event in state.event_log.iter() {
            if let SavedEvent::ExecutionPoint(execution_point) = event {
                execution_point.prepare(segment)?;
            }
        }
        self.cvar.notify_all();
        Ok(())
    }

    /// Wait until N new event becomes available. Intended to be called by
    /// checker workers.
    fn wait_until_n_events_available(&self, n: EventPos) -> Result<MutexGuard<State>> {
        let mut state = self.state.lock();
        let init_pos = state.event_pos;

        state.is_waiting = true;
        loop {
            if state.event_pos as isize <= state.event_log.len() as isize - n as isize {
                state.is_waiting = false;

                if state.event_pos < init_pos {
                    // Rewind occurs. Cancelling execution.
                    return Err(Error::Cancelled);
                }
                return Ok(state);
            } else if state.main_status == MainStatus::Completed {
                state.is_waiting = false;

                if state.event_pos < state.event_log.len() {
                    return Ok(state);
                } else {
                    return Err(Error::UnexpectedEvent(UnexpectedEventReason::Excess));
                }
            } else if state.main_status == MainStatus::Crashed {
                state.is_waiting = false;

                return Err(Error::Cancelled);
            }

            self.cvar.wait(&mut state);
        }
    }

    pub fn wait_for_initial_event(&self) -> Result<()> {
        if self.enable_async_events {
            let _ = self.wait_until_n_events_available(1)?;
        }

        Ok(())
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

    pub fn push_event(
        &self,
        event: impl Into<SavedEvent>,
        is_last: bool,
        segment: &Segment,
    ) -> Result<()> {
        let event: SavedEvent = event.into();

        match &event {
            SavedEvent::ExecutionPoint(exec_point) => {
                exec_point.prepare(segment)?;
                assert!(self.enable_async_events);
            }

            _ => (),
        };

        let mut state = self.state.lock();
        assert_eq!(state.main_status, MainStatus::Filling);
        state.event_log.push(event);

        if is_last {
            if let Some(incomplete_syscall) = state.last_incomplete_syscall.take() {
                state
                    .event_log
                    .push(SavedEvent::IncompleteSyscall(Arc::new(incomplete_syscall)));
            }

            state.main_status = MainStatus::Completed;
        }

        self.cvar.notify_all();

        Ok(())
    }

    /// Get the next syscall in the segment, waiting for the main worker to push
    /// if there is none. Intended to be called by checker workers.
    pub fn get_syscall(&self) -> Result<Arc<SavedSyscall>> {
        let state = self.wait_until_event_available()?;

        state
            .event_log
            .get(state.event_pos)
            .unwrap()
            .get_syscall()
            .ok_or(Error::UnexpectedEvent(
                UnexpectedEventReason::IncorrectTypeOrArguments,
            ))
            .map(|syscall| syscall.clone())
    }

    pub fn get_incomplete_syscall(&self) -> Result<Arc<SavedIncompleteSyscall>> {
        let state = self.wait_until_event_available()?;

        state
            .event_log
            .get(state.event_pos)
            .unwrap()
            .get_incomplete_syscall()
            .ok_or(Error::UnexpectedEvent(
                UnexpectedEventReason::IncorrectTypeOrArguments,
            ))
            .map(|incomplete_syscall| incomplete_syscall.clone())
    }

    pub fn get_last_incomplete_syscall(&self) -> Option<Arc<SavedIncompleteSyscall>> {
        let state = self.state.lock();

        state
            .event_log
            .last()
            .and_then(|event| event.get_incomplete_syscall())
    }

    fn pop_event_with<T>(
        &self,
        f: impl FnOnce(&SavedEvent) -> Option<T>,
    ) -> Result<WithIsLastEvent<T>> {
        let mut state = self.wait_until_event_available()?;

        let event = state.event_log.get(state.event_pos).unwrap();

        let ret = f(event).ok_or(Error::UnexpectedEvent(
            UnexpectedEventReason::IncorrectTypeOrArguments,
        ))?;

        state.event_pos += 1;

        let is_last_event = (state.event_pos == state.event_log.len())
            && state.main_status == MainStatus::Completed;

        Ok(WithIsLastEvent::new(is_last_event, ret))
    }

    pub fn pop_syscall(&self) -> Result<WithIsLastEvent<Arc<SavedSyscall>>> {
        self.pop_event_with(|event| event.get_syscall())
    }

    pub fn pop_trap_event(&self) -> Result<WithIsLastEvent<Arc<SavedTrapEvent>>> {
        self.pop_event_with(|event| event.get_trap_event())
    }

    pub fn pop_execution_point(&self) -> Result<WithIsLastEvent<Arc<dyn ExecutionPoint>>> {
        self.pop_event_with(|event| event.get_execution_point())
    }

    pub fn pop_manual_checkpoint_request(
        &self,
    ) -> Result<WithIsLastEvent<ManualCheckpointRequest>> {
        self.pop_event_with(|event| event.get_manual_checkpoint_request())
    }

    pub fn pop_incomplete_syscall(&self) -> Result<WithIsLastEvent<Arc<SavedIncompleteSyscall>>> {
        self.pop_event_with(|event| event.get_incomplete_syscall())
    }

    pub fn peek_event_blocking(&self) -> Result<SavedEvent> {
        let state = self.wait_until_event_available()?;
        Ok(state.event_log.get(state.event_pos).unwrap().clone())
    }
}
