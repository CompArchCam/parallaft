use std::{collections::LinkedList, mem, ptr, rc::Rc};

use log::info;
use nix::unistd::Pid;

use crate::process::{Process, ProcessCloneExt};

#[derive(Debug)]
pub enum CheckpointError {
    InvalidState,
}

type Result<T> = std::result::Result<T, CheckpointError>;

#[derive(Debug)]
pub enum CheckpointKind {
    Subsequent { reference: Rc<Process> },
    Initial,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub kind: CheckpointKind,
    pub epoch: u32,
}

impl Checkpoint {
    pub fn new(epoch: u32, reference: Rc<Process>) -> Self {
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
        checker: Rc<Process>,
    },
    ReadyToCheck {
        checker: Rc<Process>,
        checkpoint_end: Rc<Checkpoint>,
    },
    Checked {
        checkpoint_end: Rc<Checkpoint>,
    },
}

impl SegmentStatus {
    pub fn mark_as_ready(&mut self, checkpoint_end: Rc<Checkpoint>) -> Result<()> {
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
    pub checkpoint_start: Rc<Checkpoint>,
    pub status: SegmentStatus,
}

impl Segment {
    pub fn new(checkpoint_start: Rc<Checkpoint>, checker: Rc<Process>) -> Self {
        Self {
            checkpoint_start,
            status: SegmentStatus::New { checker },
        }
    }

    /// Mark this segment as "ready to check".
    /// This should happen when the main process reaches the ending checkpoint of this segment, i.e. the checkpoint immediately after the starting checkpoint.
    pub fn mark_as_ready(&mut self, checkpoint_end: Rc<Checkpoint>) -> Result<()> {
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
    pub segments: LinkedList<Segment>,
    pub main: Rc<Process>,
    pub epoch: u32,
    is_last_checkpoint_finishing: bool,
    checker_cpu_affinity: &'c Vec<usize>,
}

impl<'c> CheckCoordinator<'c> {
    pub fn new(main: Process, checker_cpu_affinity: &'c Vec<usize>) -> Self {
        Self {
            main: Rc::new(main),
            segments: LinkedList::new(),
            epoch: 0,
            is_last_checkpoint_finishing: true,
            checker_cpu_affinity,
        }
    }

    /// Lookup not-checked segment by its checker PID
    pub fn lookup_segment_by_checker_pid_mut<'a>(
        &'a mut self,
        pid: Pid,
    ) -> Option<&'a mut Segment> {
        self.segments
            .iter_mut()
            .find(|s| s.checker().map_or(false, |c| c.pid == pid))
    }

    pub fn handle_sigchld(&mut self, to_pid: Pid, from_pid: Pid) -> bool {
        if to_pid == self.main.pid && self.main.zombie_children.borrow().contains(&from_pid) {
            self.main.reap_zombie_child(from_pid);
            true
        } else {
            false
        }
    }

    /// Handle checkpoint request from the target
    pub fn handle_checkpoint(&mut self, pid: Pid, is_finishing: bool) {
        if pid == self.main.pid {
            if !is_finishing {
                let checker = self.main.clone_process();

                let checkpoint = match self.is_last_checkpoint_finishing {
                    true => Checkpoint::new_initial(self.epoch),
                    false => Checkpoint::new(self.epoch, checker.clone_process()),
                };

                checker.set_cpu_affinity(self.checker_cpu_affinity);
                checker.clear_dirty_page_bits();
                self.main.clear_dirty_page_bits();

                info!("New checkpoint: {:?}", checkpoint);
                self.add_checkpoint(checkpoint, Some(checker));
                self.is_last_checkpoint_finishing = false;
            } else {
                if !self.is_last_checkpoint_finishing {
                    let checkpoint = Checkpoint::new(self.epoch, self.main.clone_process());
                    info!("New checkpoint: {:?}", checkpoint);
                    self.add_checkpoint(checkpoint, None);
                }

                self.is_last_checkpoint_finishing = true;
            }

            self.epoch += 1;
            self.main.resume();
        } else if let Some(segment) = self.lookup_segment_by_checker_pid_mut(pid) {
            info!("Checker called checkpoint");
            let result = segment.check().unwrap();

            if !result {
                panic!("check fails");
            }
            info!("Check passed");
            self.cleanup_committed_segments();
        } else {
            panic!("invalid pid");
        }
    }

    fn cleanup_committed_segments(&mut self) {
        loop {
            let mut should_break = true;
            let front = self.segments.front();
            if let Some(front) = front {
                if let SegmentStatus::Checked { .. } = front.status {
                    self.segments.pop_front();
                    should_break = false;
                }
            }
            if should_break {
                break;
            }
        }
    }

    fn add_checkpoint(&mut self, checkpoint: Checkpoint, checker: Option<Rc<Process>>) {
        let checkpoint = Rc::new(checkpoint);
        if let Some(last_segment) = self.segments.back_mut() {
            last_segment.mark_as_ready(checkpoint.clone()).unwrap();
            last_segment.checker().unwrap().resume();
        }

        if let Some(checker) = checker {
            let segment = Segment::new(checkpoint, checker);
            info!("New segment: {:?}", segment);
            self.segments.push_back(segment);
        }
    }

    /// Check if all checkers has finished.
    pub fn is_all_finished(&mut self) -> bool {
        self.segments.is_empty()
    }
}
