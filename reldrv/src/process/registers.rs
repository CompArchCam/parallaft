use crate::error::Result;
use nix::libc::{self, user_regs_struct};
use std::{
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use syscalls::{SyscallArgs, Sysno};

use super::Process;

#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Registers {
    pub inner: user_regs_struct,

    #[cfg(target_arch = "aarch64")]
    pub sysno: libc::c_int,
}

impl Deref for Registers {
    type Target = user_regs_struct;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl DerefMut for Registers {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.inner
    }
}

impl Registers {
    #[cfg(target_arch = "x86_64")]
    pub fn new(gpr: user_regs_struct) -> Self {
        Self { inner: gpr }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn new(gpr: user_regs_struct, sysno: libc::c_int) -> Self {
        Self { inner: gpr, sysno }
    }

    pub fn sysno(&self) -> Option<Sysno> {
        Sysno::new(self.sysno_raw())
    }

    pub fn with_sysno(self, nr: Sysno) -> Self {
        self.with_sysno_raw(nr.id() as _)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall_args(&self) -> SyscallArgs {
        SyscallArgs::new(
            self.rdi as _,
            self.rsi as _,
            self.rdx as _,
            self.r10 as _,
            self.r8 as _,
            self.r9 as _,
        )
    }

    #[cfg(target_arch = "aarch64")]
    pub fn syscall_args(&self) -> SyscallArgs {
        SyscallArgs::new(
            self.regs[0] as _,
            self.regs[1] as _,
            self.regs[2] as _,
            self.regs[3] as _,
            self.regs[4] as _,
            self.regs[5] as _,
        )
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_syscall_args(mut self, args: SyscallArgs) -> Self {
        self.rdi = args.arg0 as _;
        self.rsi = args.arg1 as _;
        self.rdx = args.arg2 as _;
        self.r10 = args.arg3 as _;
        self.r8 = args.arg4 as _;
        self.r9 = args.arg5 as _;

        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_syscall_args(mut self, args: SyscallArgs) -> Self {
        self.regs[0] = args.arg0 as _;
        self.regs[1] = args.arg1 as _;
        self.regs[2] = args.arg2 as _;
        self.regs[3] = args.arg3 as _;
        self.regs[4] = args.arg4 as _;
        self.regs[5] = args.arg5 as _;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn sysno_raw(&self) -> usize {
        self.orig_rax as _
    }

    #[cfg(target_arch = "aarch64")]
    pub fn sysno_raw(&self) -> usize {
        self.sysno as _
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_sysno_raw(mut self, nr: usize) -> Self {
        self.orig_rax = nr as _;
        self.rax = nr as _;
        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_sysno_raw(mut self, nr: usize) -> Self {
        self.sysno = nr as _;
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn syscall_ret_val(&self) -> isize {
        self.rax as _
    }

    #[cfg(target_arch = "aarch64")]
    pub fn syscall_ret_val(&self) -> isize {
        self.regs[0] as _
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_syscall_ret_val(mut self, ret_val: isize) -> Self {
        self.rax = ret_val as _;
        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_syscall_ret_val(mut self, ret_val: isize) -> Self {
        self.regs[0] = ret_val as _;
        self
    }

    /// Skip the syscall by rewriting the current sysno to a nonexistent one.
    #[cfg(target_arch = "x86_64")]
    pub fn with_syscall_skipped(mut self) -> Self {
        self.orig_rax = 0xff77 as _;
        self.rax = 0xff77 as _;

        self
    }

    /// Skip the syscall by rewriting the current sysno to a nonexistent one.
    #[cfg(target_arch = "aarch64")]
    pub fn with_syscall_skipped(mut self) -> Self {
        self.sysno = -1;
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_tsc(mut self, tsc: u64) -> Self {
        self.rax = tsc & 0xffff_ffffu64;
        self.rdx = tsc >> 32;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_tscp(mut self, tsc: u64, aux: u32) -> Self {
        self.rax = tsc & 0xffff_ffffu64;
        self.rdx = tsc >> 32;
        self.rcx = aux as _;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_offsetted_ip(mut self, offset: isize) -> Self {
        self.rip = self.rip.wrapping_add_signed(offset as _);

        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_offsetted_ip(mut self, offset: isize) -> Self {
        self.pc = self.pc.wrapping_add_signed(offset as _);

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_ip(mut self, rip: usize) -> Self {
        self.rip = rip as _;

        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_ip(mut self, rip: usize) -> Self {
        self.pc = rip as _;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_cpuid_result(mut self, cpuid_result: CpuidResult) -> Self {
        self.rax = cpuid_result.eax as _;
        self.rbx = cpuid_result.ebx as _;
        self.rcx = cpuid_result.ecx as _;
        self.rdx = cpuid_result.edx as _;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn cpuid_leaf_subleaf(&self) -> (u32, u32) {
        (self.rax as _, self.rcx as _)
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_resume_flag_cleared(mut self) -> Self {
        self.eflags = !(1 << 16) & self.eflags;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn ip(self) -> usize {
        self.rip as _
    }

    #[cfg(target_arch = "aarch64")]
    pub fn ip(self) -> usize {
        self.pc as _
    }

    #[cfg(target_arch = "x86_64")]
    pub fn sp(self) -> u64 {
        self.rsp
    }

    #[cfg(target_arch = "aarch64")]
    pub fn sp(self) -> u64 {
        self.sp
    }

    #[cfg(target_arch = "aarch64")]
    pub fn x7(self) -> u64 {
        self.regs[7]
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_x7(mut self, x7: u64) -> Registers {
        self.regs[7] = x7;
        self
    }
}

impl Process {
    fn get_reg_set<T>(&self, which: i32) -> Result<T> {
        let mut regs = MaybeUninit::<T>::uninit();

        let mut iov = libc::iovec {
            iov_base: regs.as_mut_ptr() as *mut _,
            iov_len: core::mem::size_of::<T>(),
        };

        unsafe {
            syscalls::syscall!(
                Sysno::ptrace,
                libc::PTRACE_GETREGSET,
                self.pid.as_raw(),
                which,
                &mut iov as *mut _
            )?
        };

        debug_assert_eq!(iov.iov_len, core::mem::size_of::<T>());

        Ok(unsafe { regs.assume_init() })
    }

    fn set_reg_set<T>(&self, which: i32, regs: &T) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: regs as *const _ as *mut _,
            iov_len: core::mem::size_of::<T>(),
        };

        unsafe {
            syscalls::syscall!(
                Sysno::ptrace,
                libc::PTRACE_SETREGSET,
                self.pid.as_raw(),
                which,
                &mut iov as *mut _
            )?
        };

        Ok(())
    }

    #[cfg(target_arch = "x86_64")]
    pub fn read_registers(&self) -> Result<Registers> {
        Ok(Registers::new(self.get_reg_set(libc::NT_PRSTATUS)?))
    }

    #[cfg(target_arch = "aarch64")]
    pub fn read_registers(&self) -> Result<Registers> {
        Ok(Registers::new(
            self.get_reg_set(libc::NT_PRSTATUS)?,
            self.get_reg_set(0x404 /* NT_ARM_SYSTEM_CALL */)?,
        ))
    }

    /// Read the correct x7 in syscall-stops for aarch64
    pub fn read_registers_precise(&self) -> Result<Registers> {
        #[cfg(target_arch = "aarch64")]
        use crate::process::memory::instructions;

        use nix::sys::ptrace;

        #[cfg(target_arch = "aarch64")]
        use nix::sys::{signal::Signal, wait::WaitStatus};

        match ptrace::getsyscallinfo(self.pid)?.op {
            #[cfg(target_arch = "aarch64")]
            ptrace::SyscallInfoOp::Entry { .. } => {
                // syscall entry
                let mut regs = self.read_registers()?;

                self.write_registers(regs.with_syscall_skipped())?;
                self.resume()?;

                // syscall exit
                let status = self.waitpid()?;
                assert!(matches!(status, WaitStatus::PtraceSyscall(_)));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Exit { .. }
                ));

                // inject a breakpoint
                let old_instr = self.instr_inject(instructions::TRAP)?;
                self.resume()?;

                // expect the injected breakpoint
                let status = self.waitpid()?;
                assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)));

                // read the unclobbered x7 register
                let x7 = self.read_registers()?.regs[7];
                regs.regs[7] = x7;

                // restore the original instruction
                self.instr_restore(old_instr)?;

                // re-enter the original syscall
                self.write_registers(
                    regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize)),
                )?;
                self.resume()?;
                let status = self.waitpid()?;
                assert!(matches!(status, WaitStatus::PtraceSyscall(_)));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Entry { .. }
                ));

                #[cfg(debug_assertions)]
                {
                    let mut regs_now = self.read_registers()?;
                    regs_now.regs[7] = x7;
                    regs.sysno = regs_now.sysno;
                    assert_eq!(regs_now, regs);
                }

                Ok(regs)
            }
            #[cfg(target_arch = "aarch64")]
            ptrace::SyscallInfoOp::Exit { .. } => {
                let mut regs = self.read_registers()?;

                // inject a breakpoint
                let old_instr = self.instr_inject(instructions::TRAP)?;
                self.resume()?;

                // expect the injected breakpoint
                let status = self.waitpid()?;
                assert!(matches!(status, WaitStatus::Stopped(_, Signal::SIGTRAP)));

                // read the unclobbered x7 register
                let x7 = self.read_registers()?.regs[7];
                regs.regs[7] = x7;

                // restore the original instruction
                self.instr_restore(old_instr)?;

                // re-enter the original syscall
                self.write_registers(
                    regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize))
                        .with_syscall_skipped(),
                )?;

                // kick off the original syscall entry
                self.resume()?;

                let status = self.waitpid()?;
                assert!(matches!(status, WaitStatus::PtraceSyscall(_)));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Entry { .. }
                ));

                // syscall exit
                self.resume()?;

                let status = self.waitpid()?;
                assert!(matches!(status, WaitStatus::PtraceSyscall(_)));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Exit { .. }
                ));

                // restore the original registers
                self.write_registers(regs)?;

                Ok(regs)
            }
            _ => self.read_registers(),
        }
    }

    #[cfg(target_arch = "x86_64")]
    pub fn write_registers(&self, regs: Registers) -> Result<()> {
        self.set_reg_set(libc::NT_PRSTATUS, &regs.inner)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn write_registers(&self, regs: Registers) -> Result<()> {
        self.set_reg_set(libc::NT_PRSTATUS, &regs.inner)?;
        self.set_reg_set(0x404 /* NT_ARM_SYSTEM_CALL */, &regs.sysno)?;

        Ok(())
    }

    pub fn modify_registers_with(&self, f: impl FnOnce(Registers) -> Registers) -> Result<()> {
        let regs = self.read_registers()?;
        let regs = f(regs);
        self.write_registers(regs)?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    #[cfg(target_arch = "aarch64")]
    use crate::{error::Result, process::syscall::tests::trace};

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_read_registers_precise_syscall_entry() -> Result<()> {
        use std::arch::asm;

        use nix::sys::{ptrace, signal::Signal, wait::WaitStatus};

        let process = trace(|| {
            unsafe {
                asm!(
                    "
                        mov x7, #42
                        
                        mov w8, 0xff77
                        svc #0

                        brk #0
                    ",
                    out("x7") _,
                    out("w8") _,
                )
            };
            0
        });

        process.resume()?;

        // expect the syscall entry
        assert_eq!(process.waitpid()?, WaitStatus::PtraceSyscall(process.pid));
        assert!(matches!(
            ptrace::getsyscallinfo(process.pid)?.op,
            ptrace::SyscallInfoOp::Entry { .. }
        ));

        let mut regs = process.read_registers()?;
        let regs_precise = process.read_registers_precise()?;

        regs.regs[7] = 42;
        assert_eq!(regs, regs_precise);

        ptrace::cont(process.pid, None)?;

        // expect the breakpoint
        assert_eq!(
            process.waitpid()?,
            WaitStatus::Stopped(process.pid, Signal::SIGTRAP)
        );
        let mut regs_brk = process.read_registers()?;

        regs.regs[0] = 0;
        regs.regs[1] = 0;
        regs_brk.regs[0] = 0;
        regs_brk.regs[1] = 0;

        assert_eq!(regs_brk.regs, regs.regs);

        process.modify_registers_with(|r| r.with_offsetted_ip(4))?;

        // program exit
        ptrace::cont(process.pid, None)?;

        assert_eq!(process.waitpid()?, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }

    #[cfg(target_arch = "aarch64")]
    #[test]
    fn test_read_registers_precise_syscall_exit() -> Result<()> {
        use std::arch::asm;

        use nix::sys::{ptrace, signal::Signal, wait::WaitStatus};

        let process = trace(|| {
            unsafe {
                asm!(
                    "
                        mov x7, #42
                        
                        mov w8, 0xff77
                        svc #0

                        brk #0
                    ",
                    out("x7") _,
                    out("w8") _,
                )
            };
            0
        });

        process.resume()?;

        // expect the syscall entry
        assert_eq!(process.waitpid()?, WaitStatus::PtraceSyscall(process.pid));
        assert!(matches!(
            ptrace::getsyscallinfo(process.pid)?.op,
            ptrace::SyscallInfoOp::Entry { .. }
        ));

        process.resume()?;

        // expect the syscall exit
        assert_eq!(process.waitpid()?, WaitStatus::PtraceSyscall(process.pid));
        assert!(matches!(
            ptrace::getsyscallinfo(process.pid)?.op,
            ptrace::SyscallInfoOp::Exit { .. }
        ));

        let mut regs = process.read_registers()?;
        let regs_precise = process.read_registers_precise()?;

        regs.regs[7] = 42;
        assert_eq!(regs, regs_precise);

        ptrace::cont(process.pid, None)?;

        // expect the breakpoint
        assert_eq!(
            process.waitpid()?,
            WaitStatus::Stopped(process.pid, Signal::SIGTRAP)
        );
        let regs_brk = process.read_registers()?;

        assert_eq!(regs_brk.regs, regs.regs);

        process.modify_registers_with(|r| r.with_offsetted_ip(4))?;

        // program exit
        ptrace::cont(process.pid, None)?;

        assert_eq!(process.waitpid()?, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }
}
