use std::collections::LinkedList;
use std::fmt::{Debug, Display};
use std::sync::Arc;

use crate::check_coord::SyscallType;
use crate::error::Result;
use crate::process::state::Unowned;
use crate::process::Process;
use crate::types::checker_status::CheckerStatus;

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

impl Display for SegmentChains {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.list
            .iter()
            .try_for_each(|s| writeln!(f, "{}", s.state_as_str()))?;

        Ok(())
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

        let mut segment = None;
        if !is_finishing {
            segment = Some(Arc::new(Segment::new(
                checkpoint.clone(),
                self.next_id,
                main,
                ongoing_syscall,
                enable_async_events,
            )));
        }

        if self.in_chain {
            let last_segment = self.list.back().unwrap();
            if let Some(segment) = &segment {
                *last_segment.next.lock() = Some(segment.clone());
            }
            last_segment.mark_main_as_completed(Some(checkpoint), is_finishing);

            result.last_segment = Some(last_segment.clone());
        } else {
            assert!(!is_finishing);
        }

        if let Some(segment) = segment {
            self.next_id += 1;
            self.in_chain = true;

            // debug!("New segment: {:?}", segment);

            if let Some(last_segment) = &result.last_segment {
                *last_segment.next.lock() = Some(segment.clone());
            }

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

                let main_checker_status = front.main_checker_exec.status.lock();
                let aux_checker_all_finished = front
                    .aux_checker_exec
                    .lock()
                    .values()
                    .all(|x| x.is_finished());

                if main_checker_status.is_finished() && aux_checker_all_finished {
                    if keep_mismatch_segments
                        && matches!(
                            &*main_checker_status,
                            CheckerStatus::Checked {
                                result: Some(..),
                                ..
                            }
                        )
                    {
                        break;
                    }

                    if keep_crashed_segments
                        && matches!(&*main_checker_status, CheckerStatus::Crashed(..))
                    {
                        break;
                    }

                    if self.list.len() == 1 && front.record.get_last_incomplete_syscall().is_some()
                    {
                        break;
                    }

                    drop(main_checker_status);

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
            let checker_status = segment.main_checker_exec.status.lock();
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
            segment.mark_main_as_crashed_if_filling();
        }
    }
}
