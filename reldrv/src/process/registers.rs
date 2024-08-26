use crate::error::Result;

use nix::libc::{self, user_regs_struct};
use std::{
    fmt::Display,
    mem::MaybeUninit,
    ops::{Deref, DerefMut},
};
use syscalls::{SyscallArgs, Sysno};

use super::{memory::Instruction, state::Stopped, state::WithProcess, Process};

cfg_if::cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        use bitflags::bitflags;
        use std::arch::x86_64::CpuidResult;

        const fn bit(i: u32) -> u64 {
            1 << i
        }

        bitflags! {
            #[derive(Debug, Clone, Copy, PartialEq, Eq)]
            pub struct Eflags: u64 {
                const CF = bit(0);
                const PF = bit(2);
                const AF = bit(4);
                const ZF = bit(6);
                const SF = bit(7);
                const TF = bit(8);
                const IF = bit(9);
                const DF = bit(10);
                const OF = bit(11);
                const IOPL = bit(12) | bit(13);
                const NT = bit(14);
                const MD = bit(15);
                const RF = bit(16);
                const VM = bit(17);
                const AC = bit(18);
                const VIF = bit(19);
                const VIP = bit(20);
                const ID = bit(21);
            }
        }
    }
    else if #[cfg(target_arch = "aarch64")] {
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum Register {
            X(u8),
            SP,
        }

        impl Register {
            pub fn into_raw(self) -> u8 {
                match self {
                    Register::X(x) => x,
                    Register::SP => 31,
                }
            }

            pub fn from_raw(raw: u8) -> Self {
                match raw {
                    31 => Register::SP,
                    x => Register::X(x),
                }
            }
        }

        impl Display for Register {
            fn fmt(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
                match self {
                    Register::X(x) => write!(f, "x{}", x),
                    Register::SP => write!(f, "sp"),
                }
            }
        }
    }
}

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
    pub fn with_syscall_args(mut self, args: SyscallArgs, _keep_ret_val: bool) -> Self {
        self.rdi = args.arg0 as _;
        self.rsi = args.arg1 as _;
        self.rdx = args.arg2 as _;
        self.r10 = args.arg3 as _;
        self.r8 = args.arg4 as _;
        self.r9 = args.arg5 as _;

        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_syscall_args(mut self, args: SyscallArgs, keep_ret_val: bool) -> Self {
        if !keep_ret_val {
            self.regs[0] = args.arg0 as _;
        }

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
        self.eflags &= !(1 << 16);

        self
    }

    #[cfg(target_arch = "aarch64")]
    /// Clear the SS flag in PSTATE register for aarch64
    pub fn with_resume_flag_cleared(mut self) -> Self {
        self.pstate &= !(1 << 21);

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

    #[cfg(target_arch = "x86_64")]
    pub fn dump(&self) -> String {
        use std::fmt::Write;

        let mut s = String::new();
        writeln!(
            &mut s,
            "R15: {:#018x}     R14: {:#018x}     R13: {:#018x}     R12: {:#018x}",
            self.inner.r15, self.inner.r14, self.inner.r13, self.inner.r12
        )
        .unwrap();
        writeln!(
            &mut s,
            "R11: {:#018x}     R10: {:#018x}      R9: {:#018x}      R8: {:#018x}",
            self.inner.r11, self.inner.r10, self.inner.r9, self.inner.r8
        )
        .unwrap();
        writeln!(
            &mut s,
            "RDI: {:#018x}     RSI: {:#018x}     RBP: {:#018x}     RSP: {:#018x}",
            self.inner.rdi, self.inner.rsi, self.inner.rbp, self.inner.rsp
        )
        .unwrap();
        writeln!(
            &mut s,
            "RBX: {:#018x}     RDX: {:#018x}     RCX: {:#018x}     RAX: {:#018x}",
            self.inner.rbx, self.inner.rdx, self.inner.rcx, self.inner.rax
        )
        .unwrap();
        writeln!(
            &mut s,
            "RIP: {:#018x}  EFLAGS: {:#018x}   O_RAX: {:#018x}",
            self.inner.rip, self.inner.eflags, self.inner.orig_rax
        )
        .unwrap();
        writeln!(
            &mut s,
            "CS:  {:#018x}      FS: {:#018x}      GS: {:#018x}",
            self.inner.cs, self.inner.fs, self.inner.gs
        )
        .unwrap();
        s
    }

    #[cfg(target_arch = "aarch64")]
    pub fn dump(&self) -> String {
        use std::fmt::Write;

        let mut s = String::new();

        for i in (0..28).step_by(4) {
            writeln!(
                &mut s,
                "X{:#02}: {:#018x}     X{:#02}: {:#018x}     X{:#02}: {:#018x}     X{:#02}: {:#018x}",
                i,
                self.inner.regs[i],
                i + 1,
                self.inner.regs[i + 1],
                i + 2,
                self.inner.regs[i + 2],
                i + 3,
                self.inner.regs[i + 3],
            )
            .unwrap();
        }

        writeln!(
            &mut s,
            "X28: {:#018x}     X29: {:#018x}     X30: {:#018x}",
            self.inner.regs[28], self.inner.regs[29], self.inner.regs[30],
        )
        .unwrap();

        writeln!(
            &mut s,
            " SP: {:#018x}      PC: {:#018x}  PSTATE: {:#018x}",
            self.inner.sp, self.inner.pc, self.inner.pstate
        )
        .unwrap();
        s
    }

    pub fn strip_orig(mut self) -> Registers {
        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")]
            {
                self.orig_rax = 0;
            }
            else {
                let _ = &mut self;
            }
        }

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn strip_overflow_flag(mut self) -> Registers {
        self.eflags &= !(1 << 11);
        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn set(mut self, reg: Register, val: u64) -> Registers {
        match reg {
            Register::X(x) => self.regs[x as usize] = val,
            Register::SP => self.sp = val,
        }

        self
    }

    pub fn with_instruction_skipped_unchecked(self, instruction: Instruction) -> Registers {
        self.with_offsetted_ip(instruction.length() as _)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_sp(mut self, sp: usize) -> Registers {
        self.sp = sp as _;
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_sp(mut self, sp: usize) -> Registers {
        self.rsp = sp as _;
        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_arg0(mut self, arg: usize) -> Registers {
        self.regs[0] = arg as _;
        self
    }

    #[cfg(target_arch = "aarch64")]
    pub fn with_arg1(mut self, arg: usize) -> Registers {
        self.regs[1] = arg as _;
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_arg0(mut self, arg: usize) -> Registers {
        self.rdi = arg as _;
        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_arg1(mut self, arg: usize) -> Registers {
        self.rsi = arg as _;
        self
    }
}

pub trait RegisterAccess
where
    Self: Sized,
{
    fn read_registers(&self) -> Result<Registers>;

    /// Read the correct x7 in syscall-stops for aarch64
    fn read_registers_precise(self) -> Result<(Self, Registers)> {
        let reg = self.read_registers()?;
        Ok((self, reg))
    }

    fn write_registers(&mut self, regs: Registers) -> Result<()>;

    fn modify_registers_with(&mut self, f: impl FnOnce(Registers) -> Registers) -> Result<()> {
        let regs = self.read_registers()?;
        let regs = f(regs);
        self.write_registers(regs)?;
        Ok(())
    }
}

impl Process<Stopped> {
    pub fn get_reg_set<T>(&self, which: i32) -> Result<T> {
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

    pub fn set_reg_set_with_len<T>(&self, which: i32, regs: &T, len: usize) -> Result<()> {
        let mut iov = libc::iovec {
            iov_base: regs as *const _ as *mut _,
            iov_len: len.min(core::mem::size_of::<T>()),
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

    pub fn set_reg_set<T>(&self, which: i32, regs: &T) -> Result<()> {
        self.set_reg_set_with_len(which, regs, usize::MAX)
    }
}

impl RegisterAccess for Process<Stopped> {
    #[cfg(target_arch = "x86_64")]
    fn read_registers(&self) -> Result<Registers> {
        Ok(Registers::new(self.get_reg_set(libc::NT_PRSTATUS)?))
    }

    #[cfg(target_arch = "aarch64")]
    fn read_registers(&self) -> Result<Registers> {
        Ok(Registers::new(
            self.get_reg_set(libc::NT_PRSTATUS)?,
            self.get_reg_set(0x404 /* NT_ARM_SYSTEM_CALL */)?,
        ))
    }

    #[cfg(target_arch = "aarch64")]
    /// Read the correct x7 in syscall-stops for aarch64
    fn read_registers_precise(mut self) -> Result<(Self, Registers)> {
        use crate::process::memory::instructions;
        use crate::process::SyscallDir;
        use nix::sys::ptrace;
        use nix::sys::{signal::Signal, wait::WaitStatus};

        match self.syscall_dir()? {
            SyscallDir::Entry => {
                // syscall entry
                let mut regs = self.read_registers()?;

                self.write_registers(regs.with_syscall_skipped())?;

                // syscall exit
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Exit { .. }
                ));

                // inject a breakpoint
                let old_instr = self.instr_inject_and_jump(instructions::TRAP, false)?;

                // expect the injected breakpoint
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::Stopped(self.pid, Signal::SIGTRAP));

                // read the unclobbered x7 register
                let x7 = self.read_registers()?.regs[7];
                regs.regs[7] = x7;

                // restore the original instruction
                self.instr_restore_and_jump_back(old_instr)?;

                // re-enter the original syscall
                self.write_registers(
                    regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize)),
                )?;

                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
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

                Ok((self, regs))
            }
            SyscallDir::Exit => {
                let mut regs = self.read_registers()?;

                // inject a breakpoint
                let old_instr = self.instr_inject_and_jump(instructions::TRAP, false)?;

                // expect the injected breakpoint
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::Stopped(self.pid, Signal::SIGTRAP));

                // read the unclobbered x7 register
                let x7 = self.read_registers()?.regs[7];
                regs.regs[7] = x7;

                // restore the original instruction
                self.instr_restore_and_jump_back(old_instr)?;

                // re-enter the original syscall
                self.write_registers(
                    regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize))
                        .with_syscall_skipped(),
                )?;

                // kick off the original syscall entry
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Entry { .. }
                ));

                // syscall exit
                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();
                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));
                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    ptrace::SyscallInfoOp::Exit { .. }
                ));

                // restore the original registers
                self.write_registers(regs)?;

                Ok((self, regs))
            }
            _ => {
                let regs = self.read_registers()?;
                Ok((self, regs))
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    fn write_registers(&mut self, regs: Registers) -> Result<()> {
        self.set_reg_set(libc::NT_PRSTATUS, &regs.inner)
    }

    #[cfg(target_arch = "aarch64")]
    fn write_registers(&mut self, regs: Registers) -> Result<()> {
        self.set_reg_set(libc::NT_PRSTATUS, &regs.inner)?;
        self.set_reg_set(0x404 /* NT_ARM_SYSTEM_CALL */, &regs.sysno)?;

        Ok(())
    }
}

#[cfg(target_arch = "aarch64")]
#[cfg(test)]
mod tests {
    use super::RegisterAccess;
    use crate::test_utils::ptraced;
    use crate::{error::Result, process::state::WithProcess};
    use nix::sys::{ptrace, signal::Signal, wait::WaitStatus};
    use std::arch::asm;

    #[test]
    fn test_read_registers_precise_syscall_entry() -> Result<()> {
        let mut process = ptraced(|| {
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

        let mut status;
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();

        // expect the syscall entry
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert!(process.syscall_dir()?.is_entry());

        let mut regs = process.read_registers()?;
        let regs_precise;
        (process, regs_precise) = process.read_registers_precise()?;
        let mut regs2 = process.read_registers()?;

        regs.regs[7] = 42;
        assert_eq!(regs, regs_precise);

        regs2.regs[7] = 42;
        assert_eq!(regs2, regs_precise);

        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        // expect the breakpoint
        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTRAP));
        let mut regs_brk = process.read_registers()?;

        regs.regs[0] = 0;
        regs.regs[1] = 0;
        regs_brk.regs[0] = 0;
        regs_brk.regs[1] = 0;

        assert_eq!(regs_brk.regs, regs.regs);

        process.modify_registers_with(|r| r.with_offsetted_ip(4))?;

        // program exit
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }

    #[test]
    fn test_read_registers_precise_syscall_exit() -> Result<()> {
        let mut process = ptraced(|| {
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

        let mut status;
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();

        // expect the syscall entry
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert!(process.syscall_dir()?.is_entry());

        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();

        // expect the syscall exit
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert!(matches!(
            ptrace::getsyscallinfo(process.pid)?.op,
            ptrace::SyscallInfoOp::Exit { .. }
        ));

        let mut regs = process.read_registers()?;
        let regs_precise;
        (process, regs_precise) = process.read_registers_precise()?;
        let mut regs2 = process.read_registers()?;

        regs.regs[7] = 42;
        assert_eq!(regs, regs_precise);

        regs2.regs[7] = 42;
        assert_eq!(regs2, regs_precise);

        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        // expect the breakpoint
        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTRAP));
        let regs_brk = process.read_registers()?;

        assert_eq!(regs_brk.regs, regs.regs);

        process.modify_registers_with(|r| r.with_offsetted_ip(4))?;

        // program exit
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }
}
