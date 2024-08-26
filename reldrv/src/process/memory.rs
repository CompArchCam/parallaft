use std::ffi::c_int;

use super::{
    registers::RegisterAccess,
    state::{Stopped, WithProcess},
    Process, PAGEMASK,
};

use nix::{
    errno::Errno,
    sys::{
        mman::{MapFlags, ProtFlags},
        ptrace,
        uio::{process_vm_readv, process_vm_writev, RemoteIoVec},
    },
};
pub use reverie_syscalls::{Addr, MemoryAccess};
use syscalls::{syscall_args, Sysno};

#[cfg(target_arch = "x86_64")]
pub type RawInstruction = u128;

#[cfg(target_arch = "aarch64")]
pub type RawInstruction = u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub struct Instruction {
    pub value: RawInstruction,

    #[cfg(target_arch = "x86_64")]
    length: usize,
}

impl Instruction {
    pub const fn new(value: RawInstruction, #[cfg(target_arch = "x86_64")] length: usize) -> Self {
        Self {
            value,
            #[cfg(target_arch = "x86_64")]
            length,
        }
    }

    pub fn length(&self) -> usize {
        #[cfg(target_arch = "x86_64")]
        {
            self.length
        }

        #[cfg(target_arch = "aarch64")]
        {
            4
        }
    }
}

#[cfg(target_arch = "x86_64")]
pub mod instructions {
    use super::Instruction;

    pub const SYSCALL: Instruction = Instruction::new(0x050f, 2); /* syscall */
    pub const TRAP: Instruction = Instruction::new(0xcc, 1); /* int3 */
    pub const CPUID: Instruction = Instruction::new(0xa20f, 2); /* cpuid */
    pub const RDTSC: Instruction = Instruction::new(0x310f, 2); /* rdtsc */
    pub const RDTSCP: Instruction = Instruction::new(0xf9010f, 3); /* rdtscp */
}

#[cfg(target_arch = "aarch64")]
pub mod instructions {
    use super::Instruction;

    pub const SYSCALL: Instruction = Instruction::new(0xd4000001); /* svc #0 */
    pub const TRAP: Instruction = Instruction::new(0xd4200000); /* brk #0 */
    pub const NOP: Instruction = Instruction::new(0xd503201f); /* nop */
}

#[derive(Debug, Clone, Copy, Hash, PartialEq, Eq)]
pub struct ReplacedInstruction {
    addr: usize,
    old_word: usize,
}

#[derive(Debug, Clone, Copy)]
pub struct ReplacedInstructionWithOldIp {
    old_ip: usize,
    replaced_insn: ReplacedInstruction,
}

impl MemoryAccess for Process<Stopped> {
    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> Result<usize, reverie_syscalls::Errno> {
        let remote_iov: Vec<RemoteIoVec> = read_from
            .iter()
            .map(|io_slice| RemoteIoVec {
                base: io_slice.as_ptr() as _,
                len: io_slice.len(),
            })
            .collect();

        process_vm_readv(self.pid, write_to, &remote_iov)
            .map_err(|e| reverie_syscalls::Errno::new(e as _))
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> Result<usize, reverie_syscalls::Errno> {
        let remote_iov: Vec<RemoteIoVec> = write_to
            .iter()
            .map(|io_slice| RemoteIoVec {
                base: io_slice.as_ptr() as _,
                len: io_slice.len(),
            })
            .collect();

        process_vm_writev(self.pid, read_from, &remote_iov)
            .map_err(|e| reverie_syscalls::Errno::new(e as _))
    }
}

impl Process<Stopped> {
    #[cfg(target_arch = "x86_64")]
    pub fn instr_at(&self, addr: usize, len: usize) -> Instruction {
        let val: usize = self.read_value(Addr::from_raw(addr).unwrap()).unwrap();

        let raw_instr: RawInstruction = (val & ((1_usize << (len * 8)) - 1)) as _;
        Instruction::new(raw_instr, len)
    }

    pub fn instr_eq(&self, addr: usize, instr: Instruction) -> bool {
        self.instr_at(addr, instr.length()) == instr
    }

    #[cfg(target_arch = "aarch64")]
    pub fn instr_at(&self, addr: usize, len: usize) -> Instruction {
        assert_eq!(len, 4);
        let raw_instr: RawInstruction = self.read_value(Addr::from_raw(addr).unwrap()).unwrap();
        Instruction::new(raw_instr)
    }

    pub fn instr_inject(
        &mut self,
        instr: Instruction,
        addr: usize,
    ) -> crate::error::Result<ReplacedInstruction> {
        let old_word: usize = self.read_value(addr)?;

        assert!(instr.length() <= std::mem::size_of::<*mut std::ffi::c_void>());

        let mask = (1_usize << (instr.length() * 8)) - 1;
        let new_word = (instr.value as usize) & mask | (old_word & !mask);

        unsafe { ptrace::write(self.pid, addr as *mut _, new_word as *mut _)? };

        Ok(ReplacedInstruction { addr, old_word })
    }

    pub fn instr_inject_and_jump(
        &mut self,
        instr: Instruction,
        keep_ip: bool,
    ) -> crate::error::Result<ReplacedInstructionWithOldIp> {
        let registers = self.read_registers()?;
        let old_ip = registers.ip();

        let addr;

        if keep_ip {
            addr = old_ip;
        } else {
            // Assume the page of the current IP is executable
            addr = old_ip & *PAGEMASK;
        }

        let replaced_insn = self.instr_inject(instr, addr)?;

        self.write_registers(registers.with_ip(addr))?;

        Ok(ReplacedInstructionWithOldIp {
            old_ip,
            replaced_insn,
        })
    }

    pub fn instr_restore(&mut self, ctx: ReplacedInstruction) -> crate::error::Result<()> {
        unsafe { ptrace::write(self.pid, ctx.addr as *mut _, ctx.old_word as *mut _)? };
        Ok(())
    }

    pub fn instr_restore_and_jump_back(
        &mut self,
        ctx: ReplacedInstructionWithOldIp,
    ) -> crate::error::Result<()> {
        self.write_registers(self.read_registers()?.with_ip(ctx.old_ip))?;
        self.instr_restore(ctx.replaced_insn)?;

        Ok(())
    }

    pub fn mmap(
        self,
        addr: usize,
        len: usize,
        prot: ProtFlags,
        flags: MapFlags,
    ) -> crate::error::Result<WithProcess<Stopped, Result<usize, Errno>>> {
        let WithProcess(process, result) = self.syscall_direct(
            Sysno::mmap,
            syscall_args!(
                addr,
                len,
                prot.bits() as _,
                flags.bits() as _,
                -1 as c_int as _,
                0
            ),
            true,
            true,
            false,
        )?;

        let addr = Errno::result(result).map(|r| r as usize);

        Ok(WithProcess(process, addr))
    }

    pub fn munmap(
        self,
        addr: usize,
        len: usize,
    ) -> crate::error::Result<WithProcess<Stopped, Result<(), Errno>>> {
        let WithProcess(process, result) =
            self.syscall_direct(Sysno::munmap, syscall_args!(addr, len), true, true, false)?;

        Ok(WithProcess(process, Errno::result(result).map(|_| ())))
    }
}

#[cfg(test)]
mod tests {
    use nix::{
        sys::{
            ptrace,
            signal::{raise, Signal},
            wait::WaitStatus,
        },
        unistd::getpid,
    };

    use crate::{
        error::Result,
        process::{memory::instructions, state::WithProcess},
        test_utils::ptraced,
    };

    use super::RegisterAccess;

    #[test]
    fn test_instr_at() -> Result<()> {
        let mut process = ptraced(|| {
            getpid();
            0
        });

        let mut status;
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert!(matches!(status, WaitStatus::PtraceSyscall(_)));
        assert!(matches!(
            ptrace::getsyscallinfo(process.pid)?.op,
            ptrace::SyscallInfoOp::Entry { .. }
        ));

        let regs = process.read_registers()?;
        assert_eq!(
            process.instr_at(
                regs.ip() - instructions::SYSCALL.length(),
                instructions::SYSCALL.length()
            ),
            instructions::SYSCALL
        );

        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }

    #[test]
    fn test_instr_inject_and_restore() -> Result<()> {
        let mut process = ptraced(|| {
            raise(Signal::SIGSTOP).unwrap();
            0
        });

        // expect the SIGSTOP
        let mut status;

        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();
        assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGSTOP)));

        // inject a trap
        let mut regs = process.read_registers()?;
        let old_instr = process.instr_inject_and_jump(instructions::TRAP, false)?;

        // expect the trap
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)));

        // jump back
        process.instr_restore_and_jump_back(old_instr)?;

        let mut regs_now = process.read_registers()?;

        #[cfg(target_arch = "x86_64")]
        {
            regs_now.orig_rax = 0;
            regs.orig_rax = 0;
        }
        #[cfg(target_arch = "aarch64")]
        {
            regs_now.sysno = -1;
            regs.sysno = -1;
        }

        // check register matches
        assert_eq!(regs_now, regs);

        // program exit
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }
}
