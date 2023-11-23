pub mod cpuid;
pub mod rdtsc;

use nix::sys::signal::Signal;

use crate::error::Result;
use crate::syscall_handlers::HandlerContext;

#[allow(unused)]
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
    fn handle_signal<'s, 'p, 'segs, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        _context: &HandlerContext<'p, 'segs, 'disp, 'scope, 'env>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        Ok(SignalHandlerExitAction::NextHandler)
    }
}
