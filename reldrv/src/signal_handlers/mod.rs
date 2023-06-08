pub mod cpuid;
pub mod rdtsc;

use nix::sys::signal::Signal;

use crate::syscall_handlers::HandlerContext;

#[allow(unused)]
pub enum SignalHandlerExitAction {
    /// Try the next handler. The signal is not handled by the current handler.
    NextHandler,

    /// Continue the inferior without suppresing the signal.
    ContinueInferior,

    /// Suppress the signal and continue the inferior
    SuppressSignalAndContinueInferior,
}

pub trait SignalHandler {
    fn handle_signal(&self, _signal: Signal, _context: &HandlerContext) -> SignalHandlerExitAction {
        SignalHandlerExitAction::NextHandler
    }
}
