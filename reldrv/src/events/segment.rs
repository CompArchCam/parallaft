use std::sync::Arc;

use crate::{
    error::Result,
    process::state::{Running, Stopped},
    types::{
        checker::CheckFailReason,
        process_id::{Checker, Main},
        segment::Segment,
    },
};

use super::process_lifetime::HandlerContext;

#[allow(unused_variables)]
///
/// Events overview WITHOUT intra-segment parallelism, i.e. the checker will
/// only start execution after the main fully completes the segment.
///
/// ```text
///            created      ready          completed     checked     removed
///               |   wait    | checker exec.  | state cmp. |           |   
/// Checker       0 --------- x -------------- 1' --------- x    ...    x
///              /            .
///             /             .
/// Main  ---  0 ------------ 1 ---------- 2    ...
///            ^              ^
/// checkpoint_created_*  filled & chain_closed
/// ```
///
/// Events overview WITH intra-segment parallelism, i.e. the checker will start
/// execution as soon as the segment is created.
///
/// ```text
///       created & ready      completed     checked     removed
///               | checker exec.  | state cmp. |           |   
/// Checker       0 -------------- 1' --------- x    ...    x
///              /
///             /
/// Main  ---  0 ------------ 1 ---------- 2    ...
///            ^              ^
/// checkpoint_created_pre  filled & chain_closed
/// ```
pub trait SegmentEventHandler {
    /// Called when a checkpoint is about to be created, before forking. At this
    /// point, `main.segment` contains the last segment, if there is one.
    fn handle_checkpoint_created_pre_fork(
        &self,
        main: &mut Main<Stopped>,
        ctx: HandlerContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a checkpoint is about to be created, after forking. At this
    /// point, `main.segment` contains the last segment, if there is one.
    /// # States
    /// main: ptrace-stopped
    fn handle_checkpoint_created_post_fork(
        &self,
        main: &mut Main<Stopped>,
        ctx: HandlerContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when a segment is created, after `handle_checkpoint_created_pre`.
    /// # States
    /// main: running
    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        Ok(())
    }

    /// Called when the current segment chain is closed, i.e. the following
    /// execution of the main inferior will no longer be error-checked.
    /// # States
    /// main: running
    fn handle_segment_chain_closed(&self, main: &mut Main<Running>) -> Result<()> {
        Ok(())
    }

    /// Called when the current segment is completely executed by the main, so
    /// that the segment recorded is filled.
    /// # States
    /// main: running
    fn handle_segment_filled(&self, main: &mut Main<Running>) -> Result<()> {
        Ok(())
    }

    /// Called when the current segment is ready to be executed by the checker.
    /// # States
    /// checker: ptrace-stopped
    fn handle_segment_ready(
        &self,
        checker: &mut Checker<Stopped>,
        ctx: HandlerContext,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when the current segment is completely executed by the checker,
    /// but is not yet checked.
    /// # States
    /// checker: ptrace-stopped
    fn handle_segment_completed(&self, checker: &mut Checker<Stopped>) -> Result<()> {
        Ok(())
    }

    /// Called when the current segment is checked, i.e. the program state
    /// between the segment-end checkpoint and the checker is compared.
    /// # States
    /// checker: ptrace-stopped
    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
        check_fail_reason: &Option<CheckFailReason>,
    ) -> Result<()> {
        Ok(())
    }

    /// Called when the segment is about to be removed.
    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        Ok(())
    }
}
