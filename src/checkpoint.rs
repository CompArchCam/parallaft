use compel::syscalls::{syscall_args, Sysno};
use compel::PieLogger;

use nix::sys::signal::Signal::SIGCHLD;

use parasite::call_remote;
use parasite::commands::verify::VerifyRequest;
use parasite::commands::{Request, Response};

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::iter;
use std::rc::Rc;
use std::thread::sleep_ms;

use nix::sched::{sched_setaffinity, CpuSet};
use nix::sys::ptrace;
use nix::sys::signal::{self, raise, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};

use clap::Parser;

use log::{error, info};

use crate::compel_parasite::ParasiteCtlSetupHeaderExt;

#[derive(Debug)]
pub enum CheckpointStatus {
    New,
    /// It's ready to check from the previous checkpoint to this checkpoint
    Ready,
    /// This checkpoint has been checked
    Checked,
    /// This checkpoint has been committed
    Committed,
}

#[derive(Debug)]
pub struct Checkpoint {
    pub epoch: u32,
    pub checker_pid: Option<Pid>,
    pub ref_pid: Option<Pid>,
    pub next: Option<Rc<RefCell<Checkpoint>>>,
    pub prev: Option<Rc<RefCell<Checkpoint>>>,
}

#[derive(Debug)]
pub enum CheckingError {
    NoPreviousCheckpoint,
    AlreadyChecked,
}

impl Checkpoint {
    pub fn new_rced(
        checker_pid: Pid,
        ref_pid: Option<Pid>,
        prev: Option<Rc<RefCell<Checkpoint>>>,
    ) -> Rc<RefCell<Self>> {
        let epoch = prev.as_ref().map_or(0, |p| p.borrow().epoch + 1);

        let this = Rc::new(RefCell::new(Self {
            epoch,
            checker_pid: Some(checker_pid),
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

        let ref_pid = self.ref_pid.unwrap();

        info!("Start checking");

        let mut checker_proc =
            compel::ParasiteCtl::prepare(checker_pid.into()).expect("failed to prepare parasite");
        checker_proc.set_log_fd(pie_logger.fd_write);
        checker_proc.setup_c_header();
        checker_proc.infect(1).expect("failed to infect");

        let resp = call_remote!(
            checker_proc,
            Verify,
            VerifyRequest {
                pid: ref_pid.into()
            }
        )
        .expect("failed to call verify from main");
        checker_proc.cure().expect("failed to cure");

        checkpoint_prev.kill_checker();
        std::mem::drop(checkpoint_prev);
        self.kill_ref();

        Ok(resp.pass)
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
}
