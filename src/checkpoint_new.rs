use std::{mem, ptr, rc::Rc};

use nix::{
    sys::{
        signal::{kill, Signal},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

use crate::process::Process;

#[derive(Debug)]
pub enum CheckpointError {
    InvalidState,
}

type Result<T> = std::result::Result<T, CheckpointError>;

#[derive(Debug)]
pub enum CheckpointKind {
    Subsequent { reference: Process },
    Initial,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub kind: CheckpointKind,
    pub epoch: u32,
}

impl Checkpoint {
    pub fn new(epoch: u32, reference: Process) -> Self {
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
        checker: Process,
    },
    ReadyToCheck {
        checker: Process,
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

pub struct Segment {
    pub checkpoint_start: Rc<Checkpoint>,
    pub status: SegmentStatus,
}

impl Segment {
    pub fn new(checkpoint_start: Rc<Checkpoint>, checker: Process) -> Self {
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

    /// Mark this segment as "checked".
    /// This should happen after the checker process reaches the ending checkpoint.
    pub fn mark_as_checked(&mut self) -> Result<()> {
        self.status.mark_as_checked()
    }

    /// Compare dirty memory of the checker process and the reference process and mark the segment status as checked.
    /// This should be called after the checker process invokes the checkpoint syscall.
    pub fn check(&mut self) -> Result<bool> {
        if let SegmentStatus::ReadyToCheck {
            checker,
            checkpoint_end,
        } = &self.status
        {
            Ok(checker.dirty_page_delta_against(checkpoint_end.reference().unwrap()))
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

pub struct CheckCoordinator {
    segments: Vec<Segment>,
    pub main: Process,
    pub epoch: u32,
    is_last_checkpoint_finishing: bool,
}

impl CheckCoordinator {
    pub fn new(main: Process) -> Self {
        Self {
            main,
            segments: Vec::new(),
            epoch: 0,
            is_last_checkpoint_finishing: true,
        }
    }
    pub fn lookup_segment_by_checker_pid<'a>(&'a self, pid: Pid) -> Option<&'a Segment> {
        self.segments
            .iter()
            .find(|s| s.checker().map_or(false, |c| c.pid == pid))
    }

    pub fn lookup_segment_by_checker_pid_mut<'a>(
        &'a mut self,
        pid: Pid,
    ) -> Option<&'a mut Segment> {
        self.segments
            .iter_mut()
            .find(|s| s.checker().map_or(false, |c| c.pid == pid))
    }

    /// Check if the specified PID is one of the checkers'
    pub fn checker_pid_exists(&self, pid: Pid) -> bool {
        self.lookup_segment_by_checker_pid(pid).is_some()
    }

    pub fn handle_checkpoint(&mut self, pid: Pid) {
        if pid == self.main.pid {
            let checkpoint = match self.is_last_checkpoint_finishing {
                true => Checkpoint::new_initial(self.epoch),
                false => Checkpoint::new(self.epoch, self.main.fork()),
            };

            self.main.clear_dirty_page_bits();
            self.add_checkpoint(checkpoint, Some(self.main.fork()));

            self.is_last_checkpoint_finishing = false;
            self.epoch += 1;
        } else {
            panic!("invalid pid");
        }
    }

    pub fn handle_checkpoint_finish(&mut self, pid: Pid) {
        if pid == self.main.pid {
            if !self.is_last_checkpoint_finishing {
                let checkpoint = Checkpoint::new(self.epoch, self.main.fork());
                self.add_checkpoint(checkpoint, None);
            }

            self.is_last_checkpoint_finishing = true;
            self.epoch += 1;
        } else if let Some(segment) = self.lookup_segment_by_checker_pid_mut(pid) {
            let result = segment.check().unwrap();
            if !result {
                panic!("check fails");
            }
        } else {
            panic!("invalid pid");
        }
    }

    fn add_checkpoint(&mut self, checkpoint: Checkpoint, checker: Option<Process>) {
        let checkpoint = Rc::new(checkpoint);
        if let Some(last_segment) = self.segments.last_mut() {
            last_segment.mark_as_ready(checkpoint.clone()).unwrap();
            last_segment.checker().unwrap().resume();
        }

        if let Some(checker) = checker {
            self.segments.push(Segment::new(checkpoint, checker));
        }
    }
}
