pub mod dirty_pages;
mod memory;
mod registers;
mod stats;
mod syscall;
mod unwind;

use crate::{
    check_coord::CheckCoordinator,
    error::{Error, Result},
};
use lazy_init::Lazy;
use lazy_static::lazy_static;
use std::ops::Deref;
use std::{fmt::Debug, thread::Scope};

use nix::{
    errno::Errno,
    sched::{sched_setaffinity, CpuSet},
    sys::{
        ptrace,
        signal::{kill, Signal},
        wait::{waitpid, WaitStatus},
    },
    unistd::{getpid, Pid},
};

lazy_static! {
    pub static ref PAGESIZE: u64 = procfs::page_size();
}

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

    pub fn shell() -> Self {
        Process::new(getpid())
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

impl Clone for Process {
    fn clone(&self) -> Self {
        Self {
            pid: self.pid,
            procfs: Lazy::new(),
        }
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

#[derive(Clone, Copy)]
pub struct ProcessLifetimeHookContext<'p, 'disp, 'scope, 'env, 'modules> {
    pub process: &'p Process,
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules>,
    pub scope: &'scope Scope<'scope, 'env>,
}

#[allow(unused_variables)]
pub trait ProcessLifetimeHook {
    /// Called after spawning the main process
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after spawning a checker process
    fn handle_checker_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called before killing a checker process
    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        nr_dirty_pages: Option<usize>,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after all subprocesses exit
    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after main exits
    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        ret_val: i32,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }
}
