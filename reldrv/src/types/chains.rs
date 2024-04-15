use std::collections::LinkedList;
use std::fmt::Debug;
use std::mem;
use std::sync::Arc;

use log::debug;
use parking_lot::lock_api::{ArcRwLockReadGuard, ArcRwLockWriteGuard};
use parking_lot::{RawRwLock, RwLock};

use crate::error::Result;
use crate::types::checker::CheckerStatus;
use crate::types::segment::SegmentStatus;

use super::checkpoint::Checkpoint;
use super::segment::{Segment, SegmentId};

#[derive(Debug)]
pub struct SegmentChains {
    pub list: LinkedList<Arc<RwLock<Segment>>>,
    pub next_id: SegmentId,
    in_chain: bool,
}

impl Default for SegmentChains {
    fn default() -> Self {
        Self::new()
    }
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

    /// Check if there are any checking errors in this segment chain.
    pub fn has_errors(&self) -> bool {
        self.list.iter().any(|segment| segment.read().has_errors())
    }

    pub fn has_state_mismatches(&self) -> bool {
        self.list
            .iter()
            .any(|segment| segment.read_recursive().has_state_mismatches())
    }

    pub fn is_empty(&self) -> bool {
        self.list.is_empty()
    }

    pub fn len(&self) -> usize {
        self.list.len()
    }

    pub fn last_segment(&self) -> Option<Arc<RwLock<Segment>>> {
        self.list.back().cloned()
    }

    pub fn first_segment(&self) -> Option<Arc<RwLock<Segment>>> {
        self.list.front().cloned()
    }

    pub fn in_chain(&self) -> bool {
        self.in_chain
    }

    pub fn add_checkpoint(
        &mut self,
        checkpoint: Checkpoint,
        is_finishing: bool,
        on_segment_ready: impl FnOnce(
            ArcRwLockWriteGuard<RawRwLock, Segment>,
            &Checkpoint,
        ) -> Result<bool>,
        on_segment_created: impl FnOnce(ArcRwLockReadGuard<RawRwLock, Segment>) -> Result<()>,
        on_segment_chain_closed: impl FnOnce(ArcRwLockReadGuard<RawRwLock, Segment>) -> Result<()>,
        on_cleanup_needed: impl FnOnce(&mut Self) -> Result<()>,
    ) -> Result<()> {
        let checkpoint = Arc::new(checkpoint);
        let mut do_cleanup = false;

        if let Some(last_segment) = self.list.back() {
            let mut last_segment = last_segment.write_arc();

            if matches!(last_segment.status, SegmentStatus::Filling) {
                last_segment.mark_as_done(checkpoint.clone());
                do_cleanup = on_segment_ready(last_segment, &checkpoint)?;
            }
        }

        if !is_finishing {
            let segment = Segment::new(checkpoint, self.next_id);
            self.next_id += 1;
            self.in_chain = true;

            debug!("New segment: {:?}", segment);

            let segment_arc = Arc::new(RwLock::new(segment));
            let segment_mg = segment_arc.read_arc_recursive();
            self.list.push_back(segment_arc);
            on_segment_created(segment_mg)?;
        } else {
            let last_segment = self.list.back().unwrap().read_arc_recursive();
            self.in_chain = false;
            on_segment_chain_closed(last_segment)?;
        }

        if do_cleanup {
            on_cleanup_needed(self)?;
        }

        Ok(())
    }

    pub fn cleanup_committed_segments(
        &mut self,
        keep_failed_segments: bool,
        on_segment_removed: impl Fn(&Segment) -> Result<()>,
    ) -> Result<()> {
        loop {
            let mut should_break = true;
            let front = self.list.front();
            if let Some(front) = front {
                let front = front.read();
                if front.checker.is_finished() {
                    if keep_failed_segments
                        && matches!(
                            front.checker.status,
                            CheckerStatus::Checked(Some(..)) | CheckerStatus::Crashed(..)
                        )
                    {
                        break;
                    }
                    on_segment_removed(&front)?;
                    mem::drop(front);
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

    pub fn main_segment(&self) -> Option<Arc<RwLock<Segment>>> {
        if self.in_chain {
            self.list.back().cloned()
        } else {
            None
        }
    }

    /// Get the total number of dirty pages in this segment chain.
    pub fn nr_dirty_pages(&self) -> usize {
        self.list
            .iter()
            .map(|segment| {
                let segment = segment.read();
                segment.dirty_page_addresses_main.len()
            })
            .sum()
    }

    /// Mark all filling segments as crashed
    pub fn mark_all_filling_segments_as_crashed(&self) {
        for segment in &self.list {
            let mut segment = segment.write();
            if matches!(segment.status, SegmentStatus::Filling) {
                segment.status = SegmentStatus::Crashed;
            }
        }
    }
}
