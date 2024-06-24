use nix::{sys::signal::Signal, unistd::Pid};

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContext,
    },
    process::Process,
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
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if let InferiorRefMut::Main(main) = context.child {
            if main.process.get_sigval()? == Some(Self::SIGVAL_BEGIN_PROTECTION)
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

pub fn main_begin_protection_req(main_pid: Pid) -> Result<()> {
    Process::new(main_pid).sigqueue(BeginProtectionHandler::SIGVAL_BEGIN_PROTECTION)
}
