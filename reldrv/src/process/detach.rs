
use nix::sys::{ptrace, signal::Signal, wait::WaitStatus};

use super::{
    memory::{instructions, ReplacedInstructionWithOldIp},
    registers::{RegisterAccess, Registers},
    state::{ProcessState, Stopped, WithProcess},
    Process, SyscallDir,
};
use crate::error::Result;

/// State (e.g. registers) saved for a detached process for later restoration
#[derive(Debug, Clone)]
struct SavedState {
    instr: ReplacedInstructionWithOldIp,
    registers: Registers,
    syscall_dir: SyscallDir,
}

#[derive(Debug, Clone)]
pub struct Detached(SavedState);
impl ProcessState for Detached {}

impl Process<Stopped> {
    pub fn detach(mut self) -> Result<Process<Detached>> {
        let registers;
        (self, registers) = self.read_registers_precise()?;

        let saved_ctx = self.instr_inject_and_jump(instructions::TRAP, false)?;
        let syscall_dir = self.syscall_dir()?;

        if syscall_dir == SyscallDir::Entry {
            // Skip the syscall for now
            self.modify_registers_with(|r| r.with_syscall_skipped())?;

            let status;
            WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

            assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));

            debug_assert_eq!(self.syscall_dir()?, SyscallDir::Exit);
        }

        let status;
        WithProcess(self, status) = self.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Stopped(self.pid, Signal::SIGTRAP));

        ptrace::detach(self.pid, Signal::SIGSTOP)?;

        Ok(unsafe {
            self.with_state(Detached(SavedState {
                instr: saved_ctx,
                registers,
                syscall_dir,
            }))
        })
    }
}

impl Process<Detached> {
    pub fn attach(self) -> Result<Process<Stopped>> {
        let state = self.state.0.clone();

        let process = unsafe { self.seize()?.assume_running() };
        let WithProcess(mut process, status) = process.waitpid()?.unwrap_stopped();

        assert_eq!(
            status,
            WaitStatus::PtraceEvent(process.pid, Signal::SIGSTOP, nix::libc::PTRACE_EVENT_STOP)
        );

        process.instr_restore_and_jump_back(state.instr)?;

        if state.syscall_dir == SyscallDir::Entry {
            process = process.restart_to_syscall_entry_stop(
                state.registers.ip() - instructions::SYSCALL.length(),
            )?;
        }

        process.write_registers(state.registers)?;

        Ok(process)
    }

    pub fn borrow_with<F, R>(self, f: F) -> Result<WithProcess<Detached, R>>
    where
        F: FnOnce(Process<Stopped>) -> WithProcess<Stopped, R>,
    {
        let process = self.attach()?;
        let WithProcess(process, ret) = f(process);
        Ok(WithProcess(process.detach()?, ret))
    }

    pub fn try_borrow_with<F, R>(self, f: F) -> Result<WithProcess<Detached, R>>
    where
        F: FnOnce(Process<Stopped>) -> Result<WithProcess<Stopped, R>>,
    {
        let process = self.attach()?;
        let WithProcess(process, ret) = f(process)?;
        Ok(WithProcess(process.detach()?, ret))
    }
}

// impl RegisterAccess for Process<Detached> {
//     fn read_registers(&self) -> Result<Registers> {
//         Ok(self.state.0.registers.clone())
//     }

//     fn write_registers(&mut self, _regs: Registers) -> Result<()> {
//         panic!("Cannot write registers to a detached process")
//     }
// }
