use nix::sys::signal::Signal;

use super::HandlerContextWithInferior;

use crate::{error::Result, process::state::Stopped};

pub enum SignalHandlerExitAction {
    /// Try the next handler. The signal is not handled by the current handler.
    NextHandler,

    /// Continue the inferior without suppresing the signal.
    ContinueInferior,

    /// Suppress the signal and continue the inferior
    SuppressSignalAndContinueInferior { single_step: bool },

    /// Skip ptrace syscall.
    SkipPtraceSyscall,

    /// Checkpoint.
    Checkpoint,
}

pub trait SignalHandler: Sync {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        let _ = signal;
        let _ = context;
        Ok(SignalHandlerExitAction::NextHandler)
    }
}
