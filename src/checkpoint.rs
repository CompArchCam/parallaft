use compel::PieLogger;

use parasite::call_remote;
use parasite::commands::verify::VerifyRequest;

use std::cell::RefCell;
use std::rc::Rc;

use nix::sys::ptrace;
use nix::sys::signal::{self, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::Pid;

use log::{error, info};

use crate::compel_parasite::ParasiteCtlSetupHeaderExt;
use crate::dirty_page_tracer;
use crate::page_diff::{page_diff, PageDiffResult};
use crate::utils::format_vec_pointer;

#[derive(Debug, PartialEq, Eq)]
pub enum CheckpointStatus {
    New,
    /// This checkpoint has been checked
    Checked,
    /// This checkpoint has been committed
    Committed,
    /// This checkpoint is not checkable against the previous one (e.g. when it is the first checkpoint)
    NotCheckable,
}

#[derive(Debug, PartialEq, Eq)]
pub enum CheckerStatus {
    /// Checker is running and has not reached the next checkpoint
    Running,
    /// Checker has reached to the next checkpoint
    Finished,
    /// Checker has been killed (usually after checking)
    Killed,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub status: CheckpointStatus,
    pub epoch: u32,
    pub checker_pid: Option<Pid>,
    pub checker_status: CheckerStatus,
    pub ref_pid: Option<Pid>,
    pub next: Option<Rc<RefCell<Checkpoint>>>,
    pub prev: Option<Rc<RefCell<Checkpoint>>>,
}

#[derive(Debug)]
pub enum CheckingError {
    NoPreviousCheckpoint,
    AlreadyChecked,
    LastCheckerNotFinished,
}

impl Checkpoint {
    pub fn new_rced(
        checker_pid: Pid,
        ref_pid: Option<Pid>,
        prev: Option<Rc<RefCell<Checkpoint>>>,
    ) -> Rc<RefCell<Self>> {
        let epoch = prev.as_ref().map_or(0, |p| p.borrow().epoch + 1);

        let this = Rc::new(RefCell::new(Self {
            status: match &prev {
                Some(_) => CheckpointStatus::New,
                None => CheckpointStatus::NotCheckable,
            },
            epoch,
            checker_pid: Some(checker_pid),
            checker_status: CheckerStatus::Running,
            ref_pid,
            prev,
            next: None,
        }));

        if let Some(prev) = &this.borrow().prev {
            prev.as_ref().borrow_mut().next = Some(this.clone());
        }

        this
    }

    pub fn try_check_from_prev(&mut self, pie_logger: &PieLogger) -> Result<bool, CheckingError> {
        let checkpoint_prev = self
            .prev
            .as_ref()
            .ok_or(CheckingError::NoPreviousCheckpoint)?;

        let mut checkpoint_prev = checkpoint_prev.as_ref().borrow_mut();

        let checker_pid = checkpoint_prev
            .checker_pid
            .ok_or(CheckingError::AlreadyChecked)?;

        if checkpoint_prev.checker_status == CheckerStatus::Running {
            return Err(CheckingError::LastCheckerNotFinished);
        }

        let ref_pid = self.ref_pid.unwrap();

        let mut pass = false;

        // TODO: remove this
        assert_eq!(self.status, CheckpointStatus::New);

        info!(
            "Checker {:?} finished, start checking against reference {:?}",
            checker_pid, ref_pid
        );

        // TODO: reuse global variable
        let dirty_pages_checker =
            dirty_page_tracer::DirtyPageTracer::new(checker_pid.into()).get_dirty_pages();

        let dirty_pages_ref =
            dirty_page_tracer::DirtyPageTracer::new(ref_pid.into()).get_dirty_pages();

        info!(
            "Reference process dirty pages {}",
            format_vec_pointer(&dirty_pages_ref)
        );

        info!(
            "Checker process dirty pages {}",
            format_vec_pointer(&dirty_pages_checker)
        );

        let result =
            page_diff(checker_pid, ref_pid, &dirty_pages_checker, &dirty_pages_ref).unwrap();

        let pass = result == PageDiffResult::Equal;

        if !pass {
            error!("Page does not match: {:?}", result);
        }

        // let mut checker_proc =
        //     compel::ParasiteCtl::prepare(checker_pid.into()).expect("failed to prepare parasite");
        // checker_proc.set_log_fd(pie_logger.fd_write);
        // checker_proc.setup_c_header();
        // checker_proc.infect(1).expect("failed to infect");

        // let resp = call_remote!(
        //     checker_proc,
        //     Verify,
        //     VerifyRequest {
        //         pid: ref_pid.into()
        //     }
        // )
        // .expect("failed to call verify from main");
        // checker_proc.cure().expect("failed to cure");

        checkpoint_prev.kill_checker();
        std::mem::drop(checkpoint_prev);
        self.kill_ref();

        self.status = CheckpointStatus::Checked;

        Ok(pass) // TODO
    }

    pub fn kill_checker(&mut self) {
        let checker_pid = self.checker_pid.take().unwrap();
        info!("Killing checker {:?}", checker_pid);
        ptrace::kill(checker_pid).unwrap();
        let status = waitpid(checker_pid, None).unwrap();
        assert!(matches!(
            status,
            WaitStatus::Signaled(_, Signal::SIGKILL, false)
        ));
        // info!("Checker waitpid status = {:?}", status);
    }

    pub fn kill_ref(&mut self) {
        let ref_pid = self.ref_pid.take().unwrap();
        info!("Killing reference {:?}", ref_pid);
        signal::kill(ref_pid, Signal::SIGKILL).unwrap();
        let status = waitpid(ref_pid, None).unwrap();
        assert!(matches!(
            status,
            WaitStatus::Signaled(_, Signal::SIGKILL, false)
        ));
        // info!("Ref waitpid status = {:?}", status);
    }

    pub fn mark_checker_as_finished(&mut self) {
        assert_eq!(self.checker_status, CheckerStatus::Running);
        self.checker_status = CheckerStatus::Finished;
    }
}
