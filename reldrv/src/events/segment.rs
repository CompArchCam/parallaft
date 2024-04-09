use nix::unistd::Pid;

use crate::{
    error::Result,
    types::segment::{Segment, SegmentId},
};

#[allow(unused_variables)]
pub trait SegmentEventHandler {
    fn handle_segment_created(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_chain_closed(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_ready(&self, segment: &mut Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_checked(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Segment) -> Result<()> {
        Ok(())
    }

    fn handle_checkpoint_created_pre(
        &self,
        main_pid: Pid,
        last_segment_id: Option<SegmentId>,
    ) -> Result<()> {
        Ok(())
    }
}
