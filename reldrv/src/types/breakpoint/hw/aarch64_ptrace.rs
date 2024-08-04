use log::debug;
use nix::unistd::Pid;

use crate::{
    error::{Error, Result},
    process::{siginfo::SigInfoExt, Process},
    types::breakpoint::Breakpoint,
};

pub struct HardwareBreakpointViaPtrace {
    addr: usize,
    size: usize,
    watch: bool,
    slot: Option<usize>,
}

impl HardwareBreakpointViaPtrace {
    pub fn new(_pid: Pid, addr: usize, size: usize, watch: bool) -> std::io::Result<Self> {
        Ok(Self {
            addr,
            size,
            watch,
            slot: None,
        })
    }
}

#[derive(Debug, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
struct dbg_reg {
    addr: u64,
    ctrl: u32,
    _pad: u32,
}

#[derive(Debug, Clone)]
#[repr(C)]
#[allow(non_camel_case_types)]
struct user_hwdebug_state {
    dbg_info: u32,
    pad: u32,
    dbg_regs: [dbg_reg; 16],
}

impl Breakpoint for HardwareBreakpointViaPtrace {
    fn addr(&self) -> usize {
        self.addr
    }

    fn enable(&mut self, process: &mut Process) -> Result<()> {
        if self.slot.is_some() {
            return Ok(());
        }

        let regset = if self.watch {
            0x403 /* NT_ARM_HW_WATCH */
        } else {
            0x402 /* NT_ARM_HW_BREAK */
        };

        let mut reg: user_hwdebug_state = process.get_reg_set(regset)?;
        debug!("Current debug state: {:#?}", reg);

        let slot = reg.dbg_regs.iter().position(|r| r.addr == 0).unwrap();
        let max_slots = reg.dbg_info & 0xff;

        debug!("Max slots: {}", max_slots);
        debug!("Free slot: {}", slot);

        if slot > max_slots as usize {
            return Err(Error::NotSupported("no free watchpoint slots".to_string()));
        }

        let ctrl;
        if self.watch {
            let offset = (self.addr % 8) as u64;
            let byte_mask = ((1u32 << self.size) - 1) << offset;
            if byte_mask >= 1u32 << 8 {
                return Err(Error::NotSupported("watchpoint size too large".to_string()));
            }

            ctrl = 1 /* enabled */ | 2 /* write */ << 3 | byte_mask << 5;
        } else {
            ctrl = 1 /* enabled */;
        }

        reg.dbg_regs[slot] = dbg_reg {
            addr: self.addr as u64,
            ctrl,
            _pad: 0,
        };

        debug!("New debug state: {:#?}", reg);

        self.slot = Some(slot);

        process.set_reg_set_with_len(
            regset,
            &reg,
            8 + std::mem::size_of::<dbg_reg>() * max_slots as usize,
        )?;

        Ok(())
    }

    fn disable(&mut self, process: &mut Process) -> Result<()> {
        if let Some(slot) = self.slot {
            let regset = if self.watch {
                0x403 /* NT_ARM_HW_WATCH */
            } else {
                0x402 /* NT_ARM_HW_BREAK */
            };

            let mut reg: user_hwdebug_state = process.get_reg_set(regset)?;
            debug!("Current debug state: {:#?}", reg);

            let max_slots = reg.dbg_info & 0xff;

            reg.dbg_regs[slot] = dbg_reg {
                addr: 0,
                ctrl: 0,
                _pad: 0,
            };

            debug!("New debug state: {:#?}", reg);

            process.set_reg_set_with_len(
                regset,
                &reg,
                8 + std::mem::size_of::<dbg_reg>() * max_slots as usize,
            )?;

            self.slot = None;
        }

        Ok(())
    }

    fn is_hit(&self, process: &Process) -> Result<bool> {
        let siginfo = process.get_siginfo()?;
        Ok(siginfo.is_trap_hwbp() && unsafe { siginfo.si_addr() } as usize == self.addr)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use std::{arch::asm, ffi::c_void};

    use nix::sys::{signal::Signal, wait::WaitStatus};
    use syscalls::Sysno;

    use crate::{
        error::Result,
        process::{registers::RegisterAccess, SyscallDir},
        test_utils::{init_logging, ptraced},
    };

    #[test]
    fn test_watchpoint() -> Result<()> {
        init_logging();

        let mut a = 0xdeadbeef_usize;

        let mut process = ptraced(|| {
            unsafe {
                asm!(
                    "
                    mov x9, #42
                    str x9, [{a}]
                    mov w8, #172
                    svc #0
                    mov x9, #43
                    str x9, [{a}]
                    ",
                    a = in(reg) &a,
                    out("x0") _,
                    out("x8") _,
                    out("x9") _,
                );
            }

            0
        });

        // set up watchpoint
        let mut bp = HardwareBreakpointViaPtrace::new(
            process.pid,
            &mut a as *mut usize as usize,
            std::mem::size_of::<usize>(),
            true,
        )?;

        bp.enable(&mut process)?;
        process.resume()?;

        // expect watchpoint hit
        let status = process.waitpid()?;
        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTRAP));
        let siginfo = process.get_siginfo()?;
        let addr = unsafe { siginfo.si_addr() };
        assert_eq!(addr, &mut a as *mut _ as *mut c_void);
        assert!(bp.is_hit(&process)?);
        bp.disable(&mut process)?;
        process.single_step()?;

        // re-enable watchpoint
        let status = process.waitpid()?;
        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTRAP));
        bp.enable(&mut process)?;
        process.resume()?;

        // expect getpid entry
        let status = process.waitpid()?;
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(process.read_registers()?.sysno(), Some(Sysno::getpid));
        assert_eq!(process.syscall_dir()?, SyscallDir::Entry);
        process.resume()?;

        // expect getpid exit
        let status = process.waitpid()?;
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(process.syscall_dir()?, SyscallDir::Exit);
        process.resume()?;

        // expect watchpoint to be hit again
        let status = process.waitpid()?;
        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTRAP));
        let siginfo = process.get_siginfo()?;
        let addr = unsafe { siginfo.si_addr() };
        assert_eq!(addr, &mut a as *mut _ as *mut c_void);
        assert!(bp.is_hit(&process)?);
        bp.disable(&mut process)?;
        process.cont()?;

        // expect exit
        let status = process.waitpid()?;
        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }
}
