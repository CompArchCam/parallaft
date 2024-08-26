pub mod detach;
pub mod dirty_pages;
pub mod madvise;
pub mod memory;
pub mod registers;
pub mod siginfo;
pub mod sigqueue;
pub mod state;
mod stats;
mod syscall;

use crate::error::{Error, Result};
use derivative::Derivative;
use lazy_init::Lazy;
use lazy_static::lazy_static;
use memory::instructions::SYSCALL;
use nix::sys::wait::WaitPidFlag;
use nix::unistd::gettid;
use pidfd::PidFd;
use registers::{RegisterAccess, Registers};
use state::{ProcessState, Running, Stopped, Unowned, WithProcess};
use std::fmt::Debug;

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

use self::memory::instructions;

lazy_static! {
    pub static ref PAGESIZE: usize = procfs::page_size() as _;
    pub static ref PAGEMASK: usize = !(*PAGESIZE - 1);
}

struct ProcessHandles {
    pub procfs: Lazy<procfs::ProcResult<procfs::process::Process>>,
    pub pidfd: Lazy<std::io::Result<PidFd>>,
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct Process<S: ProcessState> {
    pub pid: Pid,
    #[derivative(Debug = "ignore")]
    handles: Option<ProcessHandles>,
    state: S,
    owned: bool,
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SyscallDir {
    Entry,
    Exit,
    None,
}

#[derive(Debug)]
pub struct SavedSyscallContext {
    dir: SyscallDir,
    regs: Registers,
}

impl SyscallDir {
    pub fn is_entry(&self) -> bool {
        *self == SyscallDir::Entry
    }

    pub fn is_exit(&self) -> bool {
        *self == SyscallDir::Exit
    }
}

impl<S: ProcessState> Process<S> {
    pub fn new(pid: Pid, state: S) -> Self {
        let owned = state.is_owned();

        Self {
            pid,
            handles: Some(ProcessHandles {
                procfs: Lazy::new(),
                pidfd: Lazy::new(),
            }),
            state,
            owned,
        }
    }

    pub unsafe fn with_state<S2: ProcessState>(mut self, state: S2) -> Process<S2> {
        let handles = self.handles.take().unwrap();

        self.owned = false;

        let owned = state.is_owned();

        Process {
            pid: self.pid,
            handles: Some(handles),
            state,
            owned,
        }
    }

    pub unsafe fn assume_running(self) -> Process<Running> {
        self.with_state(Running)
    }

    pub unsafe fn assume_stopped(self) -> Process<Stopped> {
        self.with_state(Stopped)
    }

    pub fn unowned_copy(&self) -> Process<Unowned> {
        Process {
            pid: self.pid,
            handles: Some(ProcessHandles {
                procfs: Lazy::new(),
                pidfd: Lazy::new(),
            }),
            state: Unowned,
            owned: false,
        }
    }

    pub fn procfs(&self) -> Result<&procfs::process::Process> {
        let p = self
            .handles
            .as_ref()
            .unwrap()
            .procfs
            .get_or_create(|| procfs::process::Process::new(self.pid.as_raw()))
            .as_ref()
            .map_err(|_| Error::Other)?;

        Ok(p)
    }

    pub fn pidfd(&self) -> Result<&PidFd> {
        let pidfd = self
            .handles
            .as_ref()
            .unwrap()
            .pidfd
            .get_or_create(|| unsafe { PidFd::open(self.pid.as_raw(), 0) })
            .as_ref()
            .map_err(|_| Error::Other)?;

        Ok(pidfd)
    }

    pub fn kill(self) -> Result<Process<Running>> {
        self.kill_with_sig(Signal::SIGKILL)?;
        Ok(unsafe { self.assume_running() })
    }

    pub fn kill_with_sig(&self, sig: Signal) -> Result<()> {
        kill(self.pid, sig)?;
        Ok(())
    }

    pub fn set_cpu_affinity(&mut self, cpus: &[usize]) -> Result<()> {
        if !cpus.is_empty() {
            let mut cpuset = CpuSet::new();
            for cpu in cpus {
                cpuset.set(*cpu)?;
            }
            sched_setaffinity(self.pid, &cpuset)?;
        }
        Ok(())
    }

    pub fn seize(self) -> std::result::Result<Self, Errno> {
        ptrace::seize(
            self.pid,
            ptrace::Options::PTRACE_O_TRACESYSGOOD
                | ptrace::Options::PTRACE_O_TRACECLONE
                | ptrace::Options::PTRACE_O_TRACEFORK
                | ptrace::Options::PTRACE_O_EXITKILL,
        )?;

        Ok(self)
    }

    /// Forget the process without killing it.
    pub fn forget(self) {
        unsafe { self.with_state(Unowned) };
    }
}

impl Process<Stopped> {
    pub fn single_step(self) -> Result<Process<Running>> {
        ptrace::step(self.pid, None)?;
        Ok(unsafe { self.assume_running() })
    }

    pub fn resume(self) -> Result<Process<Running>> {
        ptrace::syscall(self.pid, None)?;
        Ok(unsafe { self.assume_running() })
    }

    pub fn resume_with_signal(self, signal: Signal) -> Result<Process<Running>> {
        ptrace::cont(self.pid, Some(signal))?;
        Ok(unsafe { self.assume_running() })
    }

    pub fn cont(self) -> Result<Process<Running>> {
        ptrace::cont(self.pid, None)?;
        Ok(unsafe { self.assume_running() })
    }

    pub fn syscall_dir(&self) -> std::result::Result<SyscallDir, Errno> {
        Ok(match ptrace::getsyscallinfo(self.pid)?.op {
            ptrace::SyscallInfoOp::Entry { .. } => SyscallDir::Entry,
            ptrace::SyscallInfoOp::Exit { .. } => SyscallDir::Exit,
            _ => SyscallDir::None,
        })
    }

    pub fn restart_to_syscall_entry_stop(
        mut self,
        syscall_instr_ip: usize,
    ) -> Result<Process<Stopped>> {
        match self.syscall_dir()? {
            SyscallDir::Entry => Ok(self),
            SyscallDir::Exit => todo!("Process::setup_syscall_entry with syscall-exit-stop"),
            SyscallDir::None => {
                debug_assert!(self.instr_eq(syscall_instr_ip, instructions::SYSCALL));

                self.modify_registers_with(|r| r.with_syscall_skipped().with_ip(syscall_instr_ip))?;

                // Syscall entry
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Entry);

                Ok(self)
            }
        }
    }

    pub fn restart_to_syscall_exit_stop(
        mut self,
        syscall_instr_ip: usize,
    ) -> Result<Process<Stopped>> {
        match self.syscall_dir()? {
            SyscallDir::Entry => todo!("Process::setup_syscall_exit with syscall-entry-stop"),
            SyscallDir::Exit => Ok(self),
            SyscallDir::None => {
                debug_assert!(self.instr_eq(syscall_instr_ip, instructions::SYSCALL));

                self.modify_registers_with(|r| r.with_syscall_skipped().with_ip(syscall_instr_ip))?;

                // Syscall entry
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Entry);

                // Syscall exit
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Exit);

                Ok(self)
            }
        }
    }

    pub fn save_syscall_context(&mut self) -> crate::error::Result<SavedSyscallContext> {
        let regs = self.read_registers()?;

        match self.syscall_dir()? {
            SyscallDir::Entry => {
                let syscall_ip = regs.ip() - SYSCALL.length();
                debug_assert!(self.instr_eq(syscall_ip, SYSCALL));

                self.write_registers(regs.with_syscall_skipped())?;

                Ok(SavedSyscallContext {
                    dir: SyscallDir::Entry,
                    regs,
                })
            }
            SyscallDir::Exit => {
                let syscall_ip = regs.ip() - SYSCALL.length();
                debug_assert!(self.instr_eq(syscall_ip, SYSCALL));

                Ok(SavedSyscallContext {
                    dir: SyscallDir::Exit,
                    regs,
                })
            }
            SyscallDir::None => Ok(SavedSyscallContext {
                dir: SyscallDir::None,
                regs,
            }),
        }
    }

    pub fn restore_syscall_context(
        mut self,
        ctx: SavedSyscallContext,
    ) -> crate::error::Result<Process<Stopped>> {
        let regs = ctx.regs;

        match ctx.dir {
            SyscallDir::Entry => {
                let syscall_ip = regs.ip() - SYSCALL.length();

                debug_assert!(self.instr_eq(syscall_ip, SYSCALL));
                self.write_registers(regs.with_ip(syscall_ip))?;

                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Entry);
            }
            SyscallDir::Exit => {
                let regs = ctx.regs;

                let syscall_ip = regs.ip() - SYSCALL.length();

                debug_assert!(self.instr_eq(syscall_ip, SYSCALL));
                self.write_registers(regs.with_ip(syscall_ip).with_syscall_skipped())?;

                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Entry);

                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert_eq!(self.syscall_dir()?, SyscallDir::Exit);
            }
            SyscallDir::None => (),
        }

        self.write_registers(regs)?;

        Ok(self)
    }
}

impl Clone for Process<Unowned> {
    fn clone(&self) -> Self {
        Self {
            pid: self.pid,
            handles: Some(ProcessHandles {
                procfs: Lazy::new(),
                pidfd: Lazy::new(),
            }),
            state: Unowned,
            owned: false,
        }
    }
}

#[derive(Debug)]
pub enum WaitPidResult {
    Running {
        process: Process<Running>,
    },
    Stopped {
        process: Process<Stopped>,
        status: WaitStatus,
    },
}

impl WaitPidResult {
    pub fn unwrap_stopped(self) -> WithProcess<Stopped, WaitStatus> {
        match self {
            WaitPidResult::Stopped { process, status } => WithProcess(process, status),
            _ => panic!("Expected a stopped process"),
        }
    }
}

impl Process<Running> {
    pub fn interrupt(&self) -> Result<()> {
        ptrace::interrupt(self.pid)?;
        Ok(())
    }

    pub fn waitpid(self) -> std::result::Result<WaitPidResult, Errno> {
        self.waitpid_with_flags(None)
    }

    pub fn waitpid_with_flags(
        self,
        flags: Option<WaitPidFlag>,
    ) -> std::result::Result<WaitPidResult, Errno> {
        match waitpid(self.pid, flags)? {
            WaitStatus::StillAlive => Ok(WaitPidResult::Running { process: self }),
            status => Ok(WaitPidResult::Stopped {
                status,
                process: unsafe { self.assume_stopped() },
            }),
        }
    }
}

impl Process<Unowned> {
    pub fn shell() -> Process<Unowned> {
        Process::new(gettid(), Unowned)
    }
}

impl<S: ProcessState> Drop for Process<S> {
    fn drop(&mut self) {
        if self.owned {
            let result = kill(self.pid, Signal::SIGKILL);

            match result {
                Ok(_) => (),
                Err(Errno::ESRCH) => return,
                err => {
                    panic!("Failed to kill process {:?}: {:?}", self.pid, err);
                }
            }

            loop {
                let status = waitpid(self.pid, None).unwrap();

                match status {
                    WaitStatus::Exited(_, _) => break,
                    WaitStatus::Signaled(_, Signal::SIGKILL, _) => break,
                    _ => continue,
                }
            }
        }
    }
}
