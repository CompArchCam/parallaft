#[cfg(target_arch = "x86_64")]
pub mod cpuid;

#[cfg(target_arch = "x86_64")]
pub mod rdtsc;

use nix::sys::signal::Signal;

use crate::check_coord::{CheckCoordinator, ProcessIdentityRef, UpgradableReadGuard};
use crate::error::{Error, Result, UnexpectedEventReason};
use crate::segments::{SavedTrapEvent, Segment};
use crate::syscall_handlers::HandlerContext;

pub enum SignalHandlerExitAction {
    /// Try the next handler. The signal is not handled by the current handler.
    NextHandler,

    /// Continue the inferior without suppresing the signal.
    ContinueInferior,

    /// Suppress the signal and continue the inferior
    SuppressSignalAndContinueInferior,

    /// Skip ptrace syscall.
    SkipPtraceSyscall,

    /// Checkpoint.
    Checkpoint,
}

pub trait SignalHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        _context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        Ok(SignalHandlerExitAction::NextHandler)
    }
}

pub fn handle_nondeterministic_instruction<R>(
    child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
    check_coord: &CheckCoordinator,
    run_instr: impl FnOnce() -> R,
    create_event: impl FnOnce(R) -> SavedTrapEvent,
    replay_event: impl FnOnce(SavedTrapEvent) -> Result<R>,
) -> Result<R>
where
    R: Copy,
{
    let ret;
    match child {
        ProcessIdentityRef::Main(_) => {
            let segments = check_coord.segments.read();
            if let Some(segment) = segments.main_segment() {
                let mut segment = segment.write_arc();
                // Main signal, inside protection zone
                drop(segments);
                ret = run_instr();
                segment.replay.push_trap_event(create_event(ret));
            } else {
                // Main signal, outside protection zone
                ret = run_instr();
            }
        }
        ProcessIdentityRef::Checker(segment) => {
            // Checker signal
            let event = segment.with_upgraded(|segment| {
                let r = segment
                    .replay
                    .next_trap_event()
                    .ok_or(Error::UnexpectedTrap(UnexpectedEventReason::Excess))?;

                Ok::<_, Error>(*r)
            })?;

            ret = replay_event(event)?;
        }
    };

    Ok(ret)
}
