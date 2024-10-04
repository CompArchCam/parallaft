use std::sync::Arc;

use log::{error, info};
use nix::libc::siginfo_t;
use parking_lot::{Mutex, MutexGuard};

use crate::{
    error::{Error, Result, UnexpectedEventReason},
    events::signal::SignalHandlerExitAction,
    process::state::Stopped,
    types::{execution_point::ExecutionPoint, process_id::Checker},
};

use super::{
    manual_checkpoint::ManualCheckpointRequest,
    program_exit::ProgramExit,
    saved_event::{SavedEvent, SavedEventType},
    saved_signal::SavedSignal,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    saved_trap_event::SavedTrapEvent,
    MainStatus, SegmentRecord,
};

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
            SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step: false }
        }
    }
}

#[derive(Debug)]
struct State {
    is_waiting: bool,
    event_pos: usize,
}

#[derive(Debug)]
pub struct SegmentReplay {
    state: Mutex<State>,
    record: Arc<SegmentRecord>,
}

impl SegmentReplay {
    pub fn new(record: Arc<SegmentRecord>) -> Self {
        Self {
            state: Mutex::new(State {
                is_waiting: false,
                event_pos: 0,
            }),
            record,
        }
    }

    /// Rewind the checker pos to the beginning of the segment, cancelling
    /// existing checkers' execution.
    pub fn rewind(&self) -> Result<()> {
        self.state.lock().event_pos = 0;

        Ok(())
    }

    /// Wait until there are at least two uncomping events to replay, so that
    /// checkers will never go past possibly-upcoming async events, if
    /// `self.enable_async_events_support` is true. Otherwise, wait until one
    /// event is available.
    fn wait_until_event_available(&self) -> Result<MutexGuard<State>> {
        if !self.record.with_active_events {
            self.wait_until_n_events_available(1)
        } else {
            self.wait_until_n_events_available(2)
        }
    }

    /// Wait until N new event becomes available. Intended to be called by
    /// checker workers.
    fn wait_until_n_events_available(&self, n: usize) -> Result<MutexGuard<State>> {
        let mut record_state = self.record.state.lock();
        let init_pos = self.state.lock().event_pos;

        loop {
            let mut state = self.state.lock();
            if state.event_pos as isize <= record_state.event_log.len() as isize - n as isize {
                state.is_waiting = false;

                if state.event_pos < init_pos {
                    // Rewind occurs. Cancelling execution.
                    return Err(Error::Cancelled);
                }
                return Ok(state);
            } else if record_state.main_status == MainStatus::Completed {
                state.is_waiting = false;

                if state.event_pos < record_state.event_log.len() {
                    return Ok(state);
                } else {
                    return Err(Error::UnexpectedEvent(UnexpectedEventReason::Excess));
                }
            } else if record_state.main_status == MainStatus::Crashed {
                state.is_waiting = false;

                return Err(Error::Cancelled);
            }
            drop(state);

            self.record.cvar.wait(&mut record_state);
        }
    }

    pub fn wait_for_initial_event(&self, checker: &Checker<Stopped>) -> Result<()> {
        if self.record.with_active_events {
            let state = self.wait_until_n_events_available(1)?;
            assert_eq!(state.event_pos, 0);
            self.record
                .state
                .lock()
                .event_log
                .first()
                .unwrap()
                .prepare(checker)?;
        }

        Ok(())
    }

    /// Get the next syscall in the segment, waiting for the main worker to push
    /// if there is none. Intended to be called by checker workers.
    pub fn get_syscall(&self) -> Result<Arc<SavedSyscall>> {
        let state = self.wait_until_event_available()?;

        self.record
            .state
            .lock()
            .event_log
            .get(state.event_pos)
            .unwrap()
            .get_syscall()
    }

    pub fn get_incomplete_syscall(&self) -> Result<Arc<SavedIncompleteSyscall>> {
        let state = self.wait_until_event_available()?;

        self.record
            .state
            .lock()
            .event_log
            .get(state.event_pos)
            .unwrap()
            .get_incomplete_syscall()
    }

    fn pop_event_with<T>(
        &self,
        checker: &Checker<Stopped>,
        f: impl FnOnce(&SavedEvent) -> Result<T>,
    ) -> Result<WithIsLastEvent<T>> {
        let mut state = self.wait_until_event_available()?;

        let record_state = self.record.state.lock();

        let event = record_state.event_log.get(state.event_pos).unwrap();

        let ret = f(event)?;

        state.event_pos += 1;

        let is_last_event = (state.event_pos == record_state.event_log.len())
            && record_state.main_status == MainStatus::Completed;

        if self.record.with_active_events {
            if let Some(e) = record_state.event_log.get(state.event_pos) {
                e.prepare(checker)?;
            }
        }

        Ok(WithIsLastEvent::new(is_last_event, ret))
    }

    pub fn pop_syscall(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<Arc<SavedSyscall>>> {
        self.pop_event_with(checker, |event| event.get_syscall())
    }

    pub fn pop_trap_event(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<Arc<SavedTrapEvent>>> {
        self.pop_event_with(checker, |event| event.get_trap_event())
    }

    pub fn pop_execution_point(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<Arc<dyn ExecutionPoint>>> {
        self.pop_event_with(checker, |event| event.get_execution_point())
    }

    pub fn pop_manual_checkpoint_request(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<ManualCheckpointRequest>> {
        self.pop_event_with(checker, |event| event.get_manual_checkpoint_request())
    }

    pub fn pop_incomplete_syscall(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<Arc<SavedIncompleteSyscall>>> {
        self.pop_event_with(checker, |event| event.get_incomplete_syscall())
    }

    pub fn pop_event(&self, checker: &Checker<Stopped>) -> Result<WithIsLastEvent<SavedEvent>> {
        self.pop_event_with(checker, |event| Ok(event.clone()))
    }

    pub fn pop_signal(&self, checker: &Checker<Stopped>) -> Result<WithIsLastEvent<SavedSignal>> {
        self.pop_event_with(checker, |event| event.get_signal())
    }

    pub fn pop_internal_signal(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<siginfo_t>> {
        self.pop_event_with(checker, |event| event.get_signal()?.get_internal_signal())
    }

    pub fn pop_program_exit(
        &self,
        checker: &Checker<Stopped>,
    ) -> Result<WithIsLastEvent<ProgramExit>> {
        self.pop_event_with(checker, |event| event.get_program_exit())
    }

    pub fn peek_event_blocking(&self) -> Result<SavedEvent> {
        let state = self.wait_until_event_available()?;
        Ok(self
            .record
            .state
            .lock()
            .event_log
            .get(state.event_pos)
            .unwrap()
            .clone())
    }

    pub fn handle_exec_point_reached(
        &self,
        exec_point: &impl ExecutionPoint,
        checker: &mut Checker<Stopped>,
    ) -> Result<SignalHandlerExitAction> {
        let next_event = self.pop_event(checker)?;

        match &next_event.value {
            SavedEvent::Signal(SavedSignal::External(siginfo, exec_point_expected)) => {
                info!("{checker} Replaying external signal");

                if !exec_point_expected.do_eq(exec_point) {
                    error!(
                        "{checker} Exec point mismatch: {:?} != {:?}",
                        exec_point, exec_point_expected
                    );

                    return Err(Error::UnexpectedEvent(
                        UnexpectedEventReason::IncorrectValue,
                    ));
                }

                checker.process_mut().set_siginfo(&siginfo)?;

                assert!(!next_event.is_last_event);

                let sig = siginfo.si_signo.try_into()?;
                Ok(SignalHandlerExitAction::ContinueInferiorWithSignal(sig))
            }
            SavedEvent::ExecutionPoint(exec_point_expected) => {
                if !exec_point_expected.do_eq(exec_point) {
                    error!(
                        "{checker} Exec point mismatch: {:?} != {:?}",
                        exec_point, exec_point_expected
                    );

                    return Err(Error::UnexpectedEvent(
                        UnexpectedEventReason::IncorrectValue,
                    ));
                }

                if next_event.is_last_event {
                    Ok(SignalHandlerExitAction::Checkpoint)
                } else {
                    Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                        single_step: false,
                    })
                }
            }
            _ => Err(Error::UnexpectedEvent(
                UnexpectedEventReason::IncorrectType {
                    expected: SavedEventType::ExecutionPoint,
                    got: next_event.value,
                },
            )),
        }
    }

    pub fn is_waiting(&self) -> bool {
        self.state.lock().is_waiting
    }
}
