pub mod detach;
pub mod dirty_pages;
pub mod memory;
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

use self::memory::instructions;

lazy_static! {
    pub static ref PAGESIZE: usize = procfs::page_size() as _;
    pub static ref PAGEMASK: usize = !(*PAGESIZE - 1);
}

pub struct Process {
    pub pid: Pid,
    procfs: Lazy<procfs::ProcResult<procfs::process::Process>>,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SyscallDir {
    Entry,
    Exit,
    None,
}

impl SyscallDir {
    pub fn is_entry(&self) -> bool {
        *self == SyscallDir::Entry
    }

    pub fn is_exit(&self) -> bool {
        *self == SyscallDir::Exit
    }
}

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

    pub fn syscall_dir(&self) -> std::result::Result<SyscallDir, Errno> {
        Ok(match ptrace::getsyscallinfo(self.pid)?.op {
            ptrace::SyscallInfoOp::Entry { .. } => SyscallDir::Entry,
            ptrace::SyscallInfoOp::Exit { .. } => SyscallDir::Exit,
            _ => SyscallDir::None,
        })
    }

    pub fn restart_to_syscall_entry_stop(&self, syscall_instr_ip: usize) -> Result<()> {
        match self.syscall_dir()? {
            SyscallDir::Entry => Ok(()),
            SyscallDir::Exit => todo!("Process::setup_syscall_entry with syscall-exit-stop"),
            SyscallDir::None => {
                debug_assert!(self.instr_eq(syscall_instr_ip, instructions::SYSCALL));

                self.modify_registers_with(|r| r.with_syscall_skipped().with_ip(syscall_instr_ip))?;
                self.resume()?;

                // Syscall entry
                let status = self.waitpid()?;
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Entry);

                Ok(())
            }
        }
    }

    pub fn restart_to_syscall_exit_stop(&self, syscall_instr_ip: usize) -> Result<()> {
        match self.syscall_dir()? {
            SyscallDir::Entry => todo!("Process::setup_syscall_exit with syscall-entry-stop"),
            SyscallDir::Exit => Ok(()),
            SyscallDir::None => {
                debug_assert!(self.instr_eq(syscall_instr_ip, instructions::SYSCALL));

                self.modify_registers_with(|r| r.with_syscall_skipped().with_ip(syscall_instr_ip))?;
                self.resume()?;

                // Syscall entry
                let status = self.waitpid()?;
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Entry);

                self.resume()?;

                // Syscall exit
                let status = self.waitpid()?;
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Exit);

                Ok(())
            }
        }
    }

    pub fn seize(&self) -> std::result::Result<(), Errno> {
        ptrace::seize(
            self.pid,
            ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_EXITKILL,
        )
    }
}

impl AsRef<Process> for Process {
    fn as_ref(&self) -> &Process {
        self
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

impl AsRef<Process> for OwnedProcess {
    fn as_ref(&self) -> &Process {
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

        match result {
            Ok(_) => (),
            Err(Errno::ESRCH) => return,
            err => {
                panic!("Failed to kill process {:?}: {:?}", self.inner.pid, err);
            }
        }

        loop {
            let status = self.waitpid().unwrap();
            match status {
                WaitStatus::Exited(_, _) => break,
                WaitStatus::Signaled(_, Signal::SIGKILL, _) => break,
                _ => continue,
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
