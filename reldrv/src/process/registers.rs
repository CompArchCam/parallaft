use crate::error::Result;
use nix::{libc::user_regs_struct, sys::ptrace};
use std::{
    arch::x86_64::CpuidResult,
    ops::{Deref, DerefMut},
};
use syscalls::{SyscallArgs, Sysno};

use super::Process;

#[derive(Debug, Clone, Copy)]
pub struct Registers {
    pub inner: user_regs_struct,
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
    pub fn new(regs: user_regs_struct) -> Self {
        Self { inner: regs }
    }

    pub fn sysno(&self) -> Option<Sysno> {
        if cfg!(target_arch = "x86_64") {
            Sysno::new(self.sysno_raw())
        } else {
            panic!("Unsupported architecture")
        }
    }

    pub fn with_sysno(mut self, nr: Sysno) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.orig_rax = nr.id() as _;
            self.rax = nr.id() as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    pub fn syscall_args(&self) -> SyscallArgs {
        if cfg!(target_arch = "x86_64") {
            SyscallArgs::new(
                self.rdi as _,
                self.rsi as _,
                self.rdx as _,
                self.r10 as _,
                self.r8 as _,
                self.r9 as _,
            )
        } else {
            panic!("Unsupported architecture")
        }
    }

    pub fn with_syscall_args(mut self, args: SyscallArgs) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.rdi = args.arg0 as _;
            self.rsi = args.arg1 as _;
            self.rdx = args.arg2 as _;
            self.r10 = args.arg3 as _;
            self.r8 = args.arg4 as _;
            self.r9 = args.arg5 as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    pub fn sysno_raw(&self) -> usize {
        if cfg!(target_arch = "x86_64") {
            self.orig_rax as _
        } else {
            panic!("Unsupported architecture")
        }
    }

    pub fn syscall_ret_val(&self) -> isize {
        if cfg!(target_arch = "x86_64") {
            self.rax as _
        } else {
            panic!("Unsupported architecture");
        }
    }

    pub fn with_syscall_ret_val(mut self, ret_val: isize) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.rax = ret_val as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    /// Skip the syscall by rewriting the current sysno to a nonexistent one.
    pub fn with_syscall_skipped(mut self) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.orig_rax = 0xff77 as _;
            self.rax = 0xff77 as _;
        } else {
            panic!("Unsupported architecture");
        }

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

    pub fn with_offsetted_rip(mut self, offset: isize) -> Self {
        self.rip = self.rip.wrapping_add_signed(offset as _);

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

    pub fn cpuid_leaf_subleaf(&self) -> (u32, u32) {
        (self.rax as _, self.rcx as _)
    }
}

impl Process {
    pub fn read_registers(&self) -> Result<Registers> {
        Ok(Registers::new(ptrace::getregs(self.pid)?))
    }

    pub fn write_registers(&self, regs: Registers) -> Result<()> {
        ptrace::setregs(self.pid, regs.inner)?;
        Ok(())
    }

    pub fn modify_registers_with(&self, f: impl FnOnce(Registers) -> Registers) -> Result<()> {
        let regs = self.read_registers()?;
        let regs = f(regs);
        self.write_registers(regs)?;
        Ok(())
    }
}
