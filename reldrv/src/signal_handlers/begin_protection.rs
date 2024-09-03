use nix::sys::signal::Signal;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{
        state::{ProcessState, Stopped},
        Process,
    },
    types::process_id::InferiorRefMut,
};

pub struct BeginProtectionHandler;

impl BeginProtectionHandler {
    const SIGVAL_BEGIN_PROTECTION: usize = 0xfaffa2b03209b6fb;
}

impl SignalHandler for BeginProtectionHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if let InferiorRefMut::Main(main) = context.child {
            if main.process().get_sigval()? == Some(Self::SIGVAL_BEGIN_PROTECTION)
                && main.segment.is_none()
            {
                return Ok(SignalHandlerExitAction::Checkpoint);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl Module for BeginProtectionHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_signal_handler(self);
    }
}

pub fn main_begin_protection_req<S: ProcessState>(main: &Process<S>) -> Result<()> {
    main.sigqueue(BeginProtectionHandler::SIGVAL_BEGIN_PROTECTION)
}
