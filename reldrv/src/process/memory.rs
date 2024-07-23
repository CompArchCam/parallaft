use super::{registers::RegisterAccess, Process, PAGEMASK};
use nix::{
    errno::Errno,
    sys::{
        ptrace,
        uio::{process_vm_readv, process_vm_writev, RemoteIoVec},
    },
};
use reverie_syscalls::{Addr, MemoryAccess};

#[cfg(target_arch = "x86_64")]
pub type RawInstruction = u128;

#[cfg(target_arch = "aarch64")]
pub type RawInstruction = u32;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
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
}

#[derive(Debug, Clone, Copy)]
pub struct InjectedInstructionContext {
    addr: usize,
    old_pc: usize,
    old_word: u64,
}

impl MemoryAccess for Process {
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

        process_vm_readv(self.pid, write_to, &remote_iov).map_err(|e| match e {
            Errno::EFAULT => reverie_syscalls::Errno::EFAULT,
            Errno::EINVAL => reverie_syscalls::Errno::EINVAL,
            Errno::ENOMEM => reverie_syscalls::Errno::ENOMEM,
            Errno::EPERM => reverie_syscalls::Errno::EPERM,
            Errno::ESRCH => reverie_syscalls::Errno::ESRCH,
            _ => reverie_syscalls::Errno::ENODATA,
        })
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

        process_vm_writev(self.pid, read_from, &remote_iov).map_err(|e| match e {
            Errno::EFAULT => reverie_syscalls::Errno::EFAULT,
            Errno::EINVAL => reverie_syscalls::Errno::EINVAL,
            Errno::ENOMEM => reverie_syscalls::Errno::ENOMEM,
            Errno::EPERM => reverie_syscalls::Errno::EPERM,
            Errno::ESRCH => reverie_syscalls::Errno::ESRCH,
            _ => reverie_syscalls::Errno::ENODATA,
        })
    }
}

impl Process {
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
        &self,
        instr: Instruction,
    ) -> crate::error::Result<InjectedInstructionContext> {
        let registers = self.read_registers()?;
        let old_pc = registers.ip();

        // Assume the page of the current PC is executable
        let addr = old_pc & *PAGEMASK;

        let old_word: u64 = self.read_value(addr)?;

        unsafe { ptrace::write(self.pid, addr as *mut _, instr.value as *mut _)? };

        self.write_registers(registers.with_ip(addr))?;

        Ok(InjectedInstructionContext {
            addr,
            old_pc,
            old_word,
        })
    }

    pub fn instr_restore(&self, ctx: InjectedInstructionContext) -> crate::error::Result<()> {
        self.write_registers(self.read_registers()?.with_ip(ctx.old_pc))?;

        unsafe { ptrace::write(self.pid, ctx.addr as *mut _, ctx.old_word as *mut _)? };

        Ok(())
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
        process::{memory::instructions, syscall::tests::trace},
    };

    use super::RegisterAccess;

    #[test]
    fn test_instr_at() -> Result<()> {
        let process = trace(|| {
            getpid();
            0
        });

        process.resume()?;

        let status = process.waitpid()?;
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

        // program exit
        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Exited(process.pid, 0)
        );

        Ok(())
    }

    #[test]
    fn test_instr_inject_and_restore() -> Result<()> {
        let process = trace(|| {
            raise(Signal::SIGSTOP).unwrap();
            0
        });

        // expect the SIGSTOP
        ptrace::cont(process.pid, None)?;
        let status = process.waitpid()?;
        assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGSTOP)));

        // inject a trap
        let mut regs = process.read_registers()?;
        let old_instr = process.instr_inject(instructions::TRAP)?;

        ptrace::cont(process.pid, None)?;

        // expect the trap
        let status = process.waitpid()?;
        assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)));

        // jump back
        process.instr_restore(old_instr)?;

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
        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Exited(process.pid, 0)
        );

        Ok(())
    }
}
