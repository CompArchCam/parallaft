use std::ops::Deref;

use nix::sys::{ptrace, signal::Signal, wait::WaitStatus};

use super::{
    memory::{instructions, InjectedInstructionContext},
    registers::Registers,
    Process, SyscallDir,
};
use crate::error::Result;

fn attach(process: &Process, state: &SavedState) -> Result<()> {
    process.seize()?;

    assert_eq!(
        process.waitpid()?,
        WaitStatus::PtraceEvent(process.pid, Signal::SIGSTOP, nix::libc::PTRACE_EVENT_STOP)
    );

    process.instr_restore(state.instr)?;

    if state.syscall_dir == SyscallDir::Entry {
        process
            .restart_to_syscall_entry_stop(state.registers.ip() - instructions::SYSCALL.length())?;
    }

    process.write_registers(state.registers)?;

    Ok(())
}

/// State (e.g. registers) saved for a detached process for later restoration
#[derive(Debug)]
struct SavedState {
    instr: InjectedInstructionContext,
    registers: Registers,
    syscall_dir: SyscallDir,
}

fn detach(process: &Process) -> Result<SavedState> {
    let registers = process.read_registers()?;
    let saved_ctx = process.instr_inject(instructions::TRAP)?;
    let syscall_dir = process.syscall_dir()?;

    if syscall_dir == SyscallDir::Entry {
        // Skip the syscall for now
        process.modify_registers_with(|r| r.with_syscall_skipped())?;
        process.resume()?;
        assert_eq!(process.waitpid()?, WaitStatus::PtraceSyscall(process.pid));
        debug_assert_eq!(process.syscall_dir()?, SyscallDir::Exit);
    }

    ptrace::cont(process.pid, None)?;
    assert_eq!(
        process.waitpid()?,
        WaitStatus::Stopped(process.pid, Signal::SIGTRAP)
    );

    ptrace::detach(process.pid, Signal::SIGSTOP)?;

    Ok(SavedState {
        instr: saved_ctx,
        registers,
        syscall_dir,
    })
}

#[derive(Debug)]
pub struct DetachedProcess<T: AsRef<Process>> {
    inner: T,
    state: SavedState,
}

impl<T: AsRef<Process>> DetachedProcess<T> {
    pub fn detach_from(process: T) -> Result<DetachedProcess<T>> {
        let state = detach(process.as_ref())?;

        Ok(DetachedProcess {
            inner: process,
            state,
        })
    }

    pub fn attach(self) -> Result<T> {
        attach(self.inner.as_ref(), &self.state)?;
        Ok(self.inner)
    }

    pub fn borrow_with<R>(&mut self, f: impl FnOnce(&T) -> R) -> Result<R> {
        attach(self.inner.as_ref(), &self.state)?;
        let ret = f(&self.inner);
        self.state = detach(self.inner.as_ref())?;
        Ok(ret)
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
    fn detach(self) -> Result<DetachedProcess<Self>>;
}

impl<T: AsRef<Process>> ProcessDetachExt for T {
    fn detach(self) -> Result<DetachedProcess<Self>> {
        DetachedProcess::detach_from(self)
    }
}
