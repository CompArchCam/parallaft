use std::ops::Deref;

use nix::{
    sys::{
        ptrace,
        signal::Signal,
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::Pid,
};
use scopeguard::defer;

use super::{memory::instructions, OwnedProcess, Process};

fn attach(pid: Pid) {
    ptrace::seize(
        pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_EXITKILL,
    )
    .unwrap();

    assert_eq!(
        waitpid(pid, None).unwrap(),
        WaitStatus::PtraceEvent(pid, Signal::SIGSTOP, nix::libc::PTRACE_EVENT_STOP)
    );
}

fn detach(pid: Pid, already_stopped: bool /* hack */) {
    match ptrace::getsyscallinfo(pid).unwrap().op {
        ptrace::SyscallInfoOp::Entry { .. } => {
            let process = Process::new(pid);
            let registers = process.read_registers().unwrap();

            process
                .write_registers(
                    registers
                        .with_syscall_skipped()
                        .with_offsetted_ip(-(instructions::SYSCALL.length() as isize)),
                )
                .unwrap();

            process.resume().unwrap();
            assert_eq!(process.waitpid().unwrap(), WaitStatus::PtraceSyscall(pid));
            debug_assert!(matches!(
                ptrace::getsyscallinfo(pid).unwrap().op,
                ptrace::SyscallInfoOp::Exit { .. }
            ));

            process.write_registers(registers).unwrap();
        }
        ptrace::SyscallInfoOp::Exit { .. } => todo!("implement detach on syscall exit"),
        _ => (),
    }

    ptrace::detach(pid, Signal::SIGSTOP).unwrap();

    if !already_stopped {
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WUNTRACED)).unwrap(),
            WaitStatus::Stopped(pid, Signal::SIGSTOP)
        );
    }
}

#[derive(Debug)]
pub struct DetachedProcess<T: AsRef<Process>> {
    inner: T,
}

impl<T: AsRef<Process>> DetachedProcess<T> {
    pub fn from(process: T) -> DetachedProcess<T> {
        detach(process.as_ref().pid, false);
        DetachedProcess { inner: process }
    }

    pub fn attach(self) -> T {
        attach(self.pid);
        self.inner
    }

    pub fn borrow_with<R>(&mut self, f: impl FnOnce(&T) -> R) -> R {
        attach(self.pid);
        defer! {
            detach(self.pid, true)
        }
        let ret = f(&self.inner);
        ret
    }
}

impl DetachedProcess<OwnedProcess> {
    pub fn new_owned(pid: Pid) -> DetachedProcess<OwnedProcess> {
        DetachedProcess {
            inner: OwnedProcess::new(pid),
        }
    }
}

impl<T: AsRef<Process>> AsRef<Process> for DetachedProcess<T> {
    fn as_ref(&self) -> &Process {
        self.inner.as_ref()
    }
}

impl<T: AsRef<Process>> Deref for DetachedProcess<T> {
    type Target = Process;

    fn deref(&self) -> &Self::Target {
        self.as_ref()
    }
}

pub trait ProcessDetachExt
where
    Self: AsRef<Process> + Sized,
{
    fn detach(self) -> DetachedProcess<Self>;
}

impl<T: AsRef<Process>> ProcessDetachExt for T {
    fn detach(self) -> DetachedProcess<Self> {
        DetachedProcess::from(self)
    }
}
