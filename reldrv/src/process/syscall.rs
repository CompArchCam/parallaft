use log::debug;
use nix::{
    sched::CloneFlags,
    sys::{
        ptrace::{self, SyscallInfoOp},
        signal::Signal,
        wait::WaitStatus,
    },
    unistd::Pid,
};

use syscalls::{syscall_args, SyscallArgs, Sysno};

use super::{
    memory::ReplacedInstructionWithOldIp,
    registers::Registers,
    state::{Stopped, WithProcess},
    Process, SyscallDir,
};
use crate::{
    error::Result,
    process::{memory::instructions, registers::RegisterAccess, state::Running},
};

impl Process<Stopped> {
    pub fn syscall_direct(
        mut self,
        nr: Sysno,
        args: SyscallArgs,
        mut restart_parent_old_syscall: bool,
        mut restart_child_old_syscall: bool,
        force_instr_insertion: bool,
    ) -> Result<WithProcess<Stopped, i64>> {
        // save the old states
        let saved_regs;
        let saved_sigmask;

        (self, saved_regs, saved_sigmask) = Self::save_state(self)?;
        let mut saved_instr = None;

        // block signals during our injected syscall
        ptrace::setsigmask(self.pid, !0)?;

        let op = if force_instr_insertion {
            SyscallDir::None
        } else {
            self.syscall_dir()?
        };

        match op {
            SyscallDir::Entry => (),
            SyscallDir::Exit => {
                // never restart old syscalls on exit
                restart_child_old_syscall = false;
                restart_parent_old_syscall = false;

                // handle syscall exit
                debug_assert_eq!(
                    self.instr_at(
                        saved_regs.ip() - instructions::SYSCALL.length(),
                        instructions::SYSCALL.length()
                    ),
                    instructions::SYSCALL
                );

                self.write_registers(
                    saved_regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize)),
                )?; // jump back to previous syscall

                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));

                debug_assert!(self.syscall_dir()?.is_entry());
            }
            SyscallDir::None => {
                debug!("Ad-hoc syscall injection");
                // insert an ad-hoc syscall instruction
                restart_child_old_syscall = false;
                restart_parent_old_syscall = false;

                saved_instr = Some(self.instr_inject_and_jump(instructions::SYSCALL, false)?);

                let status;
                WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

                assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));

                debug_assert!(self.syscall_dir()?.is_entry());
            }
        };

        // prepare the injected syscall number and arguments
        self.write_registers(saved_regs.with_sysno(nr).with_syscall_args(args, false))?;

        // execute our injected syscall
        let mut status;
        WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

        // handle fork/clone event
        let child_pid = if let WaitStatus::PtraceEvent(pid, _sig, event) = status {
            let child_pid = Pid::from_raw(match event {
                nix::libc::PTRACE_EVENT_CLONE | nix::libc::PTRACE_EVENT_FORK => {
                    ptrace::getevent(pid)? as _
                }
                _ => panic!("Unexpected ptrace event received"),
            });

            WithProcess(self, status) = self.resume()?.waitpid()?.unwrap_stopped();

            Some(child_pid)
        } else {
            None
        };

        assert_eq!(status, WaitStatus::PtraceSyscall(self.pid));

        // get the syscall return value
        let syscall_info = ptrace::getsyscallinfo(self.pid)?;
        let syscall_ret = if let SyscallInfoOp::Exit { ret_val, .. } = syscall_info.op {
            ret_val
        } else {
            panic!("Unexpected syscall info: {:?}", syscall_info);
        };

        self = Self::restore_state(
            self,
            saved_regs,
            saved_sigmask,
            restart_parent_old_syscall,
            saved_instr,
        )?;

        if let Some(child_pid) = child_pid {
            let mut child;
            let status;

            WithProcess(child, status) =
                Process::new(child_pid, Running).waitpid()?.unwrap_stopped();

            assert!(
                matches!(status, WaitStatus::PtraceEvent(pid, sig, _ev) if pid == child_pid && sig == Signal::SIGTRAP)
            );

            child = Self::restore_state(
                child,
                saved_regs,
                saved_sigmask,
                restart_child_old_syscall,
                saved_instr,
            )?;

            child.forget();
        }

        Ok(WithProcess(self, syscall_ret))
    }

    pub fn clone_process(
        self,
        flags: CloneFlags,
        signal: Option<Signal>,
        restart_parent_old_syscall: bool,
        restart_child_old_syscall: bool,
    ) -> Result<WithProcess<Stopped, Process<Stopped>>> {
        let parent = self;

        let clone_flags: usize = flags.bits() as usize | signal.map_or(0, |x| x as usize);

        let WithProcess(parent, child_pid) = parent.syscall_direct(
            Sysno::clone,
            syscall_args!(clone_flags, 0, 0, 0, 0),
            restart_parent_old_syscall,
            restart_child_old_syscall,
            false,
        )?;

        if child_pid <= 0 {
            panic!("Unexpected pid returned from clone: {}", child_pid);
        }

        let child = Process::new(Pid::from_raw(child_pid as _), Stopped);

        Ok(WithProcess(parent, child))
    }

    pub fn fork(
        self,
        restart_parent_old_syscall: bool,
        restart_child_old_syscall: bool,
    ) -> Result<WithProcess<Stopped, Process<Stopped>>> {
        let WithProcess(parent, child) = self.clone_process(
            CloneFlags::CLONE_PTRACE | CloneFlags::CLONE_PARENT,
            None,
            restart_parent_old_syscall,
            restart_child_old_syscall,
        )?;

        Ok(WithProcess(parent, child))
    }

    fn save_state(process: Process<Stopped>) -> Result<(Process<Stopped>, Registers, u64)> {
        let (process, regs) = process.read_registers_precise()?;
        let pid = process.pid;

        Ok((process, regs, ptrace::getsigmask(pid)?))
    }

    fn restore_state(
        mut process: Process<Stopped>,
        saved_regs: Registers,
        saved_sigmask: u64,
        restart_old_syscall: bool,
        saved_instr: Option<ReplacedInstructionWithOldIp>,
    ) -> Result<Process<Stopped>> {
        if restart_old_syscall {
            let mut saved_regs = saved_regs;

            assert!(saved_instr.is_none());

            // jump back to the previous instruction
            debug_assert!(process.instr_eq(
                saved_regs.ip() - instructions::SYSCALL.length(),
                instructions::SYSCALL
            ));
            saved_regs = saved_regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize));

            #[cfg(target_arch = "x86_64")]
            {
                saved_regs.inner.rax = saved_regs.inner.orig_rax;
            }

            // restore the registers
            process.write_registers(saved_regs)?;
        } else {
            process.write_registers(saved_regs)?;
        }

        if let Some(saved_instr) = saved_instr {
            process.instr_restore_and_jump_back(saved_instr)?;
        }

        if restart_old_syscall {
            // execute the original syscall and expect the syscall event
            // TODO: handle death
            let status;

            WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
            assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));

            if cfg!(debug_assertions) {
                // expect the syscall nr
                let syscall_info = ptrace::getsyscallinfo(process.pid)?;

                let orig_nr = saved_regs.sysno_raw();

                assert!(
                    matches!(syscall_info.op, SyscallInfoOp::Entry { nr, .. } if nr == orig_nr as _)
                );
            }

            process.write_registers(saved_regs)?;
        }

        // restore the signal mask
        ptrace::setsigmask(process.pid, saved_sigmask)?;

        Ok(process)
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use nix::{
        sys::signal::raise,
        unistd::{getpid, gettid, getuid},
    };

    use crate::{process::SyscallDir, test_utils::ptraced};

    use super::*;

    #[test]
    fn test_process_syscall_injection_on_entry() -> crate::error::Result<()> {
        let mut process = ptraced(|| {
            let pid1 = getpid();
            raise(Signal::SIGSTOP).unwrap();

            // syscall is injected here
            let pid2 = getpid();

            gettid();

            if pid1 == pid2 {
                0 // pass
            } else {
                1 // fail
            }
        });

        let uid = getuid();

        let mut status;
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGSTOP));

        // second getpid entry
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));

        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        // inject a getuid syscall
        let uid2;
        WithProcess(process, uid2) = process
            .syscall_direct(Sysno::getuid, syscall_args!(), true, true, false)
            .unwrap();

        assert_eq!(uid.as_raw(), uid2 as u32);

        // second getpid exit
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));

        // gettid entry
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // program exit
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }

    #[test]
    fn test_process_syscall_injection_on_exit() -> crate::error::Result<()> {
        let mut process = ptraced(|| {
            let pid1 = getpid();
            raise(Signal::SIGSTOP).unwrap();

            // syscall is injected here
            let pid2 = getpid();

            gettid();

            if pid1 == pid2 {
                0 // pass
            } else {
                1 // fail
            }
        });

        let uid = getuid();

        let mut status;
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGSTOP));

        // second getpid entry
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));

        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        // second getpid exit
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));

        // inject a getuid syscall
        let uid2;
        WithProcess(process, uid2) = process
            .syscall_direct(Sysno::getuid, syscall_args!(), true, true, false)
            .unwrap();
        assert_eq!(uid.as_raw(), uid2 as u32);

        // gettid entry
        WithProcess(process, status) = process.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(process.pid));
        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // program exit
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();

        assert_eq!(status, WaitStatus::Exited(process.pid, 0));

        Ok(())
    }

    #[test]
    fn test_process_syscall_injection_on_exit_with_clone() -> crate::error::Result<()> {
        let mut parent = ptraced(|| {
            let pid1 = getpid();
            raise(Signal::SIGSTOP).unwrap();

            // syscall is injected here
            let pid2 = getpid();

            gettid();

            if pid1 == pid2 {
                0 // pass
            } else {
                1 // fail
            }
        });

        let mut status;

        WithProcess(parent, status) = parent.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Stopped(parent.pid, Signal::SIGSTOP));

        // second getpid entry
        WithProcess(parent, status) = parent.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(parent.pid));

        assert_eq!(
            parent.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        // second getpid exit
        WithProcess(parent, status) = parent.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(parent.pid));

        // clone the process
        let mut child;
        WithProcess(parent, child) =
            parent.clone_process(CloneFlags::CLONE_PARENT, None, false, false)?;

        // parent gettid entry
        WithProcess(parent, status) = parent.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(parent.pid));
        assert_eq!(
            parent.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // parent exit
        WithProcess(parent, status) = parent.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Exited(parent.pid, 0));

        // child gettid entry
        WithProcess(child, status) = child.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(child.pid));
        assert_eq!(
            child.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // child exit
        WithProcess(child, status) = child.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Exited(child.pid, 0));

        Ok(())
    }

    fn test_process_clone(
        restart_parent_syscall: bool,
        restart_child_syscall: bool,
    ) -> crate::error::Result<()> {
        let mut parent = ptraced(|| {
            // syscall is injected here
            getpid();

            0
        });

        let status;

        // getpid entry
        WithProcess(parent, status) = parent.resume()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::PtraceSyscall(parent.pid));

        assert_eq!(parent.read_registers()?.sysno().unwrap(), Sysno::getpid);

        assert_eq!(parent.syscall_dir()?, SyscallDir::Entry);

        let mut regs = parent.read_registers()?;

        #[cfg(target_arch = "x86_64")]
        {
            regs.inner.r8 = 0x8086;
            regs.inner.r9 = 0x8087;
            regs.inner.r10 = 0x8088;
            regs.inner.r11 = 0x8089;
            regs.inner.r12 = 0x808a;
            regs.inner.r13 = 0x808b;
            regs.inner.r14 = 0x808c;
            regs.inner.r15 = 0x808d;
            regs.inner.rax = 0x808e;
            regs.inner.rbp = 0x808f;
            regs.inner.rbx = 0x8090;
            regs.inner.rcx = 0x8091;
            regs.inner.rdi = 0x8092;
            regs.inner.rdx = 0x8093;
            regs.inner.rsi = 0x8094;
            regs.inner.rsp = 0x8095;
        }

        #[cfg(target_arch = "aarch64")]
        {
            let mut idx = 0x8085;
            regs.regs.fill_with(|| {
                idx += 1;
                idx
            });
            regs.regs[7] = 0; // we can't modify x7 during syscall-exits
            regs.sysno = regs.regs[8] as _;
        }

        parent.write_registers(regs)?;

        // clone the process
        let child;
        WithProcess(parent, child) = parent
            .clone_process(
                CloneFlags::CLONE_PARENT,
                None,
                restart_parent_syscall,
                restart_child_syscall,
            )
            .unwrap();

        if restart_parent_syscall {
            assert_eq!(parent.syscall_dir()?, SyscallDir::Entry);
        } else {
            assert_eq!(parent.syscall_dir()?, SyscallDir::Exit);
        }

        if restart_child_syscall {
            assert_eq!(child.syscall_dir()?, SyscallDir::Entry);
        } else {
            assert_eq!(child.syscall_dir()?, SyscallDir::None);
        }

        #[cfg(target_arch = "aarch64")]
        {
            let regs_precise;
            (_, regs_precise) = parent.read_registers_precise()?;
            assert_eq!(regs_precise.with_x7(0), regs);
            assert_eq!(child.read_registers()?.with_x7(0), regs);
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            assert_eq!(parent.read_registers()?, regs);
            assert_eq!(child.read_registers()?, regs);
        }

        Ok(())
    }

    #[test]
    fn test_process_clone_restart_child_syscall() -> crate::error::Result<()> {
        test_process_clone(false, true)
    }

    #[test]
    fn test_process_clone_restart_parent_syscall() -> crate::error::Result<()> {
        test_process_clone(true, false)
    }

    #[test]
    fn test_process_clone_no_syscall_restart() -> crate::error::Result<()> {
        test_process_clone(false, false)
    }

    #[test]
    fn test_process_clone_restart_both_syscall() -> crate::error::Result<()> {
        test_process_clone(true, true)
    }
}
