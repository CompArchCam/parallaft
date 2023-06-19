pub mod dirty_pages;
mod memory;
mod registers;
mod stats;
mod syscall;

#[cfg(feature = "compel")]
mod compel_parasite;

#[cfg(feature = "compel")]
mod compel;

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
    procfs: Lazy<procfs::process::Process>,
}

#[allow(unused)]
impl Process {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            procfs: Lazy::new(),
        }
    }

    pub fn procfs(&self) -> &procfs::process::Process {
        self.procfs
            .get_or_create(|| procfs::process::Process::new(self.pid.as_raw()).unwrap())
    }

    pub fn resume(&self) {
        ptrace::syscall(self.pid, None).unwrap();
    }

    pub fn interrupt(&self) {
        ptrace::interrupt(self.pid).unwrap();
    }

    pub fn set_cpu_affinity(&self, cpus: &Vec<usize>) {
        if !cpus.is_empty() {
            let mut cpuset = CpuSet::new();
            for cpu in cpus {
                cpuset.set(*cpu).unwrap();
            }
            sched_setaffinity(self.pid, &cpuset).unwrap();
        }
    }

    pub fn as_owned(self) -> OwnedProcess {
        OwnedProcess { inner: self }
    }

    pub fn waitpid(&self) -> Result<WaitStatus, Errno> {
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
