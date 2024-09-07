use std::collections::LinkedList;
use std::fmt::Debug;
use std::sync::Arc;

use log::debug;

use crate::check_coord::SyscallType;
use crate::error::Result;
use crate::process::state::Unowned;
use crate::process::Process;
use crate::types::checker::CheckerStatus;

use super::checkpoint::Checkpoint;
use super::exit_reason::ExitReason;
use super::segment::{Segment, SegmentId, SegmentStatus};

#[derive(Debug)]
pub struct SegmentChains {
    pub list: LinkedList<Arc<Segment>>,
    pub next_id: SegmentId,
    in_chain: bool,
}

impl Default for SegmentChains {
    fn default() -> Self {
        Self::new()
    }
}

pub struct AddCheckpointResult {
    pub last_segment: Option<Arc<Segment>>,
    pub new_segment: Option<Arc<Segment>>,
}

impl SegmentChains {
    pub fn new() -> Self {
        Self {
            list: LinkedList::new(),
            next_id: 0,
            in_chain: false,
        }
    }

    /// Get the number of live segments in this segment chain.
    pub fn nr_live_segments(&self) -> usize {
        self.list.len()
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn last_segment(&self) -> Option<Arc<Segment>> {
        self.list.back().cloned()
    }

    pub fn first_segment(&self) -> Option<Arc<Segment>> {
        self.list.front().cloned()
    }

    pub fn in_chain(&self) -> bool {
        self.in_chain
    }

    pub fn main_segment(&self) -> Option<Arc<Segment>> {
        self.list.back().and_then(|x| {
            if matches!(&*x.status.lock(), SegmentStatus::Filling { .. }) {
                Some(x.clone())
            } else {
                None
            }
        })
    }

    pub fn add_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        is_finishing: bool,
        main: Process<Unowned>,
        ongoing_syscall: Option<SyscallType>,
        enable_async_events: bool,
    ) -> AddCheckpointResult {
        let checkpoint = Arc::new(checkpoint);

        let mut result = AddCheckpointResult {
            last_segment: None,
            new_segment: None,
        };

        if self.in_chain {
            let last_segment = self.list.back().unwrap();
            last_segment.mark_main_as_completed(checkpoint.clone());

            result.last_segment = Some(last_segment.clone());
        } else {
            assert!(!is_finishing);
        }

        if !is_finishing {
            let segment = Segment::new(
                checkpoint,
                self.next_id,
                main,
                ongoing_syscall,
                enable_async_events,
            );

            self.next_id += 1;
            self.in_chain = true;

            debug!("New segment: {:?}", segment);

            let segment = Arc::new(segment);
            self.list.push_back(segment.clone());

            result.new_segment = Some(segment);
        } else {
            assert!(self.in_chain);
            self.in_chain = false;
        }

        result
    }

    pub fn cleanup_committed_segments(
        &mut self,
        keep_mismatch_segments: bool,
        keep_crashed_segments: bool,
        on_segment_removed: impl Fn(Arc<Segment>) -> Result<()>,
    ) -> Result<()> {
        loop {
            let mut should_break = true;
            let front = self.list.front();
            if let Some(front) = front {
                let status = front.status.lock();
                if matches!(&*status, SegmentStatus::Filling { .. }) || *front.pinned.lock() {
                    break;
                }
                drop(status);

                let checker_status = front.checker_status.lock();

                if checker_status.is_finished() {
                    if keep_mismatch_segments
                        && matches!(
                            &*checker_status,
                            CheckerStatus::Checked {
                                result: Some(..),
                                ..
                            }
                        )
                    {
                        break;
                    }

                    if keep_crashed_segments
                        && matches!(&*checker_status, CheckerStatus::Crashed(..))
                    {
                        break;
                    }

                    if self.list.len() == 1 && front.record.get_last_incomplete_syscall().is_some()
                    {
                        break;
                    }

                    drop(checker_status);

                    on_segment_removed(front.clone())?;
                    self.list.pop_front();
                    should_break = false;
                }
            }
            if should_break {
                break;
            }
        }

        Ok(())
    }

    pub fn collect_results(&self) -> Option<Result<ExitReason>> {
        for segment in &self.list {
            let checker_status = segment.checker_status.lock();
            match &*checker_status {
                CheckerStatus::Checked { result: None, .. } => (),
                CheckerStatus::Checked {
                    result: Some(r), ..
                } => return Some(Ok(ExitReason::StateMismatch(*r))),
                CheckerStatus::Crashed(error) => return Some(Err(error.clone())),
                _ => return Some(Ok(ExitReason::Cancelled)),
            }
        }

        None
    }

    /// Get the total number of dirty pages in this segment chain.
    pub fn nr_dirty_pages(&self) -> usize {
        todo!()
    }

    /// Mark all filling segments as crashed
    pub fn mark_all_filling_segments_as_crashed(&self) {
        for segment in &self.list {
            segment.mark_as_crashed_if_filling();
        }
    }
}
