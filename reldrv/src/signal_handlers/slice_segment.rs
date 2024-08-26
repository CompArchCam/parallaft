use nix::sys::signal::Signal;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    events::{
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContext,
    },
    process::{
        state::{ProcessState, Stopped},
        Process,
    },
    types::process_id::InferiorRefMut,
};

pub struct SliceSegmentHandler;

impl SliceSegmentHandler {
    const SIGVAL_DO_SLICE_SEGMENT: usize = 0x2ed6d11a6bbb1894;
}

impl SignalHandler for SliceSegmentHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if let InferiorRefMut::Main(main) = context.child {
            if main.process().get_sigval()? == Some(Self::SIGVAL_DO_SLICE_SEGMENT) {
                let ret = context
                    .check_coord
                    .push_curr_exec_point_to_event_log(main, true);

                match ret {
                    Ok(_) => return Ok(SignalHandlerExitAction::Checkpoint),
                    Err(Error::InvalidState) => {
                        return Ok(SignalHandlerExitAction::ContinueInferior)
                    }
                    Err(e) => return Err(e),
                }
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl Module for SliceSegmentHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_signal_handler(self);
    }
}

pub fn main_enqueue_slice_segment_req<S: ProcessState>(main: &Process<S>) -> Result<()> {
    main.sigqueue(SliceSegmentHandler::SIGVAL_DO_SLICE_SEGMENT)
}
