use std::{collections::LinkedList, mem, ops::DerefMut, ptr, sync::Arc};

use log::info;
use nix::unistd::Pid;

use parking_lot::{Mutex, RwLock};

#[cfg(feature = "async_check")]
use tokio::task;

use crate::process::{Process, ProcessCloneExt};

#[derive(Debug)]
pub enum CheckpointError {
    InvalidState,
}

type Result<T> = std::result::Result<T, CheckpointError>;

#[derive(Debug)]
pub enum CheckpointKind {
    Subsequent { reference: Arc<Process> },
    Initial,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub kind: CheckpointKind,
    pub epoch: u32,
}

impl Checkpoint {
    pub fn new(epoch: u32, reference: Arc<Process>) -> Self {
        Self {
            epoch,
            kind: CheckpointKind::Subsequent { reference },
        }
    }

    pub fn new_initial(epoch: u32) -> Self {
        Self {
            epoch,
            kind: CheckpointKind::Initial,
        }
    }

    pub fn reference<'a>(&'a self) -> Option<&'a Process> {
        match &self.kind {
            CheckpointKind::Subsequent { reference: ref_pid } => Some(ref_pid),
            CheckpointKind::Initial => None,
        }
    }
}

#[derive(Debug)]
pub enum SegmentStatus {
    New {
        checker: Arc<Process>,
    },
    ReadyToCheck {
        checker: Arc<Process>,
        checkpoint_end: Arc<Checkpoint>,
    },
    Checked {
        checkpoint_end: Arc<Checkpoint>,
    },
}

impl SegmentStatus {
    pub fn mark_as_ready(&mut self, checkpoint_end: Arc<Checkpoint>) -> Result<()> {
        let status = unsafe { ptr::read(self) };

        match status {
            SegmentStatus::New { checker } => {
                let new_status = SegmentStatus::ReadyToCheck {
                    checker,
                    checkpoint_end,
                };
                unsafe { ptr::write(self, new_status) };
                Ok(())
            }
            _ => {
                mem::forget(status);
                Err(CheckpointError::InvalidState)
            }
        }
    }

    pub fn mark_as_checked(&mut self) -> Result<()> {
        let status = unsafe { ptr::read(self) };

        match status {
            SegmentStatus::ReadyToCheck { checkpoint_end, .. } => {
                let new_status = SegmentStatus::Checked { checkpoint_end };
                unsafe { ptr::write(self, new_status) };
                Ok(())
            }
            _ => {
                mem::forget(status);
                Err(CheckpointError::InvalidState)
            }
        }
    }
}

#[derive(Debug)]
pub struct Segment {
    pub checkpoint_start: Arc<Checkpoint>,
    pub status: SegmentStatus,
}

impl Segment {
    pub fn new(checkpoint_start: Arc<Checkpoint>, checker: Arc<Process>) -> Self {
        Self {
            checkpoint_start,
            status: SegmentStatus::New { checker },
        }
    }

    /// Mark this segment as "ready to check".
    /// This should happen when the main process reaches the ending checkpoint of this segment, i.e. the checkpoint immediately after the starting checkpoint.
    pub fn mark_as_ready(&mut self, checkpoint_end: Arc<Checkpoint>) -> Result<()> {
        assert!(matches!(
            checkpoint_end.kind,
            CheckpointKind::Subsequent { .. }
        ));
        self.status.mark_as_ready(checkpoint_end)
    }

    /// Compare dirty memory of the checker process and the reference process and mark the segment status as checked.
    /// This should be called after the checker process invokes the checkpoint syscall.
    pub fn check(&mut self) -> Result<bool> {
        if let SegmentStatus::ReadyToCheck {
            checker,
            checkpoint_end,
        } = &self.status
        {
            let result = checker.dirty_page_delta_against(checkpoint_end.reference().unwrap());
            self.status.mark_as_checked()?;

            Ok(result)
        } else {
            Err(CheckpointError::InvalidState)
        }
    }

    /// Get the checker process, if it exists.
    pub fn checker<'a>(&'a self) -> Option<&'a Process> {
        match &self.status {
            SegmentStatus::New { checker } => Some(checker),
            SegmentStatus::ReadyToCheck { checker, .. } => Some(checker),
            _ => None,
        }
    }
}

pub struct CheckCoordinator<'c> {
    pub segments: Arc<RwLock<LinkedList<Arc<Mutex<Segment>>>>>,
    pub main: Arc<Process>,
    pub epoch: u32,
    checker_cpu_affinity: &'c Vec<usize>,
}

#[allow(unused)]
impl<'c> CheckCoordinator<'c> {
    pub fn new(main: Process, checker_cpu_affinity: &'c Vec<usize>) -> Self {
        Self {
            main: Arc::new(main),
            segments: Arc::new(RwLock::new(LinkedList::new())),
            epoch: 0,
            checker_cpu_affinity,
        }
    }

    /// Lookup not-checked segment by its checker PID
    pub fn lookup_segment_by_checker_pid_mut<'a>(&self, pid: Pid) -> Option<Arc<Mutex<Segment>>> {
        self.segments
            .read()
            .iter()
            .find(|s| s.lock().checker().map_or(false, |c| c.pid == pid))
            .map(|t| t.clone())
    }

    pub fn handle_sigchld(&self, to_pid: Pid, from_pid: Pid) -> bool {
        if to_pid == self.main.pid && self.main.zombie_children.lock().contains(&from_pid) {
            self.main.reap_zombie_child(from_pid);
            true
        } else {
            false
        }
    }

    fn is_last_checkpoint_finishing(&self) -> bool {
        let segments = self.segments.read();

        match segments.back() {
            Some(segment) => match segment.lock().status {
                SegmentStatus::New { .. } => false,
                _ => true,
            },
            None => true,
        }
    }

    /// Handle checkpoint request from the target
    pub fn handle_checkpoint(&mut self, pid: Pid, is_finishing: bool) {
        if pid == self.main.pid {
            if !is_finishing {
                let reference = self.main.clone_process();
                self.main.clear_dirty_page_bits();
                self.main.resume();

                let (checker, checkpoint) = match self.is_last_checkpoint_finishing() {
                    true => (reference, Checkpoint::new_initial(self.epoch)),
                    false => (
                        reference.clone_process(),
                        Checkpoint::new(self.epoch, reference),
                    ),
                };

                checker.set_cpu_affinity(self.checker_cpu_affinity);
                checker.clear_dirty_page_bits();

                info!("New checkpoint: {:?}", checkpoint);
                self.add_checkpoint(checkpoint, Some(checker));
            } else {
                if !self.is_last_checkpoint_finishing() {
                    let reference = self.main.clone_process();
                    self.main.resume();
                    let checkpoint = Checkpoint::new(self.epoch, reference);

                    info!("New checkpoint: {:?}", checkpoint);
                    self.add_checkpoint(checkpoint, None);
                }
            }

            self.epoch += 1;
        } else if let Some(segment) = self.lookup_segment_by_checker_pid_mut(pid) {
            info!("Checker called checkpoint");

            #[cfg(feature = "async_check")]
            {
                let segment = segment.clone();
                let segments = self.segments.clone();

                task::spawn_blocking(move || {
                    let result = segment.lock().check().unwrap();

                    if !result {
                        panic!("check fails");
                    }
                    info!("Check passed");
                    Self::cleanup_committed_segments(segments.write().deref_mut());
                });
            }

            #[cfg(not(feature = "async_check"))]
            {
                let result = segment.lock().check().unwrap();

                if !result {
                    panic!("check fails");
                }
                info!("Check passed");
                Self::cleanup_committed_segments(self.segments.write().deref_mut());
            }
        } else {
            panic!("invalid pid");
        }
    }

    fn cleanup_committed_segments(segments: &mut LinkedList<Arc<Mutex<Segment>>>) {
        loop {
            let mut should_break = true;
            let front = segments.front();
            if let Some(front) = front {
                let front = front.lock();
                if let SegmentStatus::Checked { .. } = front.status {
                    mem::drop(front);
                    segments.pop_front();
                    should_break = false;
                }
            }
            if should_break {
                break;
            }
        }
    }

    /// Create a new checkpoint and kick off the checker of the previous checkpoint if needed.
    fn add_checkpoint(&self, checkpoint: Checkpoint, checker: Option<Arc<Process>>) {
        let checkpoint = Arc::new(checkpoint);
        let mut segments = self.segments.write();

        if let Some(last_segment) = segments.back_mut() {
            let mut last_segment = last_segment.lock();
            last_segment.mark_as_ready(checkpoint.clone()).unwrap();
            last_segment.checker().unwrap().resume();
        }

        if let Some(checker) = checker {
            let segment = Segment::new(checkpoint, checker);
            info!("New segment: {:?}", segment);
            segments.push_back(Arc::new(Mutex::new(segment)));
        }
    }

    /// Check if all checkers has finished.
    pub fn is_all_finished(&self) -> bool {
        self.segments.read().is_empty()
    }
}
