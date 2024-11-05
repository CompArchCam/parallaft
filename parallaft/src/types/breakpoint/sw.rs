use cfg_if::cfg_if;
use log::debug;

use crate::{
    error::Result,
    process::{
        memory::{instructions, ReplacedInstructions},
        registers::RegisterAccess,
        state::Stopped,
        Process,
    },
};

use super::Breakpoint;

#[derive(Debug)]
enum BreakpointState {
    Disabled,
    Enabled(ReplacedInstructions),
}

pub struct SoftwareBreakpoint {
    pc: usize,
    state: BreakpointState,
}

impl SoftwareBreakpoint {
    pub fn new(process: &mut Process<Stopped>, pc: usize) -> Result<Self> {
        let mut ret = Self {
            pc,
            state: BreakpointState::Disabled,
        };
        ret.enable(process)?;
        Ok(ret)
    }
}

impl Breakpoint for SoftwareBreakpoint {
    fn addr(&self) -> usize {
        self.pc
    }

    fn enable(&mut self, process: &mut Process<Stopped>) -> Result<()> {
        if let BreakpointState::Enabled(_) = self.state {
            return Ok(());
        }

        self.state = BreakpointState::Enabled(process.insn_inject(instructions::TRAP, self.pc)?);

        #[cfg(test)]
        dbg_hex::dbg_hex!(self.pc);

        debug!("Breakpoint at PC {:#0x} enabled", self.pc);

        Ok(())
    }

    fn disable(&mut self, process: &mut Process<Stopped>) -> Result<()> {
        if let BreakpointState::Disabled = self.state {
            return Ok(());
        }

        let ctx = match std::mem::replace(&mut self.state, BreakpointState::Disabled) {
            BreakpointState::Enabled(ctx) => ctx,
            BreakpointState::Disabled => unreachable!(),
        };

        #[cfg(test)]
        dbg_hex::dbg_hex!(self.pc);

        debug!("Breakpoint at PC {:#0x} disabled", self.pc);

        process.insn_restore(ctx)?;

        Ok(())
    }

    fn is_hit(&self, process: &Process<Stopped>) -> Result<bool> {
        match self.state {
            BreakpointState::Enabled(_) => {
                let pc = process.read_registers()?.ip();
                cfg_if! {
                    if #[cfg(target_arch = "x86_64")] {
                        Ok(pc == self.pc + instructions::TRAP.length())
                    }
                    else {
                        Ok(pc == self.pc)
                    }
                }
            }
            BreakpointState::Disabled => Ok(false),
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn fix_after_hit(&self, process: &mut Process<Stopped>) -> Result<()> {
        process.modify_registers_with(|r| {
            r.with_offsetted_ip(-(instructions::TRAP.length() as isize))
        })?;

        Ok(())
    }
}

impl Drop for SoftwareBreakpoint {
    fn drop(&mut self) {
        assert!(matches!(self.state, BreakpointState::Disabled));
    }
}

#[cfg(test)]
mod tests {
    use dbg_hex::dbg_hex;
    use nix::{
        sys::{signal::Signal, wait::WaitStatus},
        unistd::{getpid, getppid},
    };
    use syscalls::Sysno;

    use crate::{
        error::Result,
        process::{
            memory::MemoryAccess, registers::RegisterAccess, state::WithProcess, SyscallDir,
        },
        test_utils::ptraced,
        types::breakpoint::Breakpoint,
    };

    use super::SoftwareBreakpoint;

    #[test]
    fn test_software_breakpoint() -> Result<()> {
        let mut process = ptraced(|| {
            getpid();
            getppid();
            0
        });

        let mut status;
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(process.syscall_dir()?, SyscallDir::Entry);
        assert_eq!(process.read_registers()?.sysno(), Some(Sysno::getpid));

        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(process.syscall_dir()?, SyscallDir::Exit);

        // Create a breakpoint at the next syscall
        let ip = process.read_registers()?.ip();
        let mut bp = SoftwareBreakpoint::new(&mut process, ip)?;
        dbg_hex!(process.read_value::<_, u64>(process.read_registers()?.ip())?);

        // Assert breakpoint has been hit
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        dbg!(process.read_registers()?.sysno());
        dbg!(process.syscall_dir()?);
        dbg_hex!(process.read_value::<_, u64>(process.read_registers()?.ip())?);

        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTRAP));
        assert!(bp.is_hit(&process)?);
        bp.fix_after_hit(&mut process)?;

        // Disable the breakpoint
        bp.disable(&mut process)?;

        // Expect the getppid syscall entry
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(process.syscall_dir()?, SyscallDir::Entry);
        assert_eq!(process.read_registers()?.sysno(), Some(Sysno::getppid));

        // Expect process exit
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }
}
