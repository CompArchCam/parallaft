pub mod dirty_pages;
mod memory;
mod registers;
mod stats;
mod syscall;

use crate::error::{Error, Result};
use lazy_init::Lazy;
use std::fmt::Debug;
use std::ops::Deref;

use nix::{
    errno::Errno,
    sched::{sched_setaffinity, CpuSet},
    sys::{
        ptrace,
        signal::{kill, Signal},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

pub struct Process {
    pub pid: Pid,
    procfs: Lazy<procfs::ProcResult<procfs::process::Process>>,
}

#[allow(unused)]
impl Process {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            procfs: Lazy::new(),
        }
    }

    pub fn procfs(&self) -> Result<&procfs::process::Process> {
        let p = self
            .procfs
            .get_or_create(|| procfs::process::Process::new(self.pid.as_raw()))
            .as_ref()
            .map_err(|_| Error::Other)?;

        Ok(p)
    }

    pub fn resume(&self) -> Result<()> {
        ptrace::syscall(self.pid, None)?;
        Ok(())
    }

    pub fn interrupt(&self) -> Result<()> {
        ptrace::interrupt(self.pid)?;
        Ok(())
    }

    pub fn set_cpu_affinity(&self, cpus: &[usize]) -> Result<()> {
        if !cpus.is_empty() {
            let mut cpuset = CpuSet::new();
            for cpu in cpus {
                cpuset.set(*cpu)?;
            }
            sched_setaffinity(self.pid, &cpuset)?;
        }
        Ok(())
    }

    pub fn as_owned(self) -> OwnedProcess {
        OwnedProcess { inner: self }
    }

    pub fn waitpid(&self) -> std::result::Result<WaitStatus, Errno> {
        waitpid(self.pid, None)
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Process").field(&self.pid.as_raw()).finish()
    }
}

pub struct OwnedProcess {
    inner: Process,
}

impl OwnedProcess {
    pub fn new(pid: Pid) -> Self {
        Self {
            inner: Process::new(pid),
        }
    }
}

impl Deref for OwnedProcess {
    type Target = Process;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Debug for OwnedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("OwnedProcess")
            .field(&self.pid.as_raw())
            .finish()
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let result = kill(self.inner.pid, Signal::SIGKILL);

        // we don't need to reap zombie children here because they will be adpoted and reaped by PID 1 anyway after this process dies

        match result {
            Ok(_) | Err(Errno::ESRCH) => (),
            err => {
                panic!("Failed to kill process {:?}: {:?}", self.inner.pid, err);
            }
        }
    }
}
