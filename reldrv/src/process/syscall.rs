use nix::{
    sched::CloneFlags,
    sys::{
        ptrace::{self, SyscallInfoOp},
        signal::Signal,
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};

use syscalls::{syscall_args, SyscallArgs, Sysno};

use super::{memory::InjectedInstructionContext, registers::Registers, Process};
use crate::{error::Result, process::memory::instructions};

impl Process {
    pub fn syscall_direct(
        &self,
        nr: Sysno,
        args: SyscallArgs,
        mut restart_parent_old_syscall: bool,
        mut restart_child_old_syscall: bool,
        force_instr_insertion: bool,
    ) -> Result<i64> {
        // save the old states
        let (saved_regs, saved_sigmask) = Self::save_state(self.pid)?;
        let mut saved_instr = None;

        let op = if force_instr_insertion {
            SyscallInfoOp::None
        } else {
            ptrace::getsyscallinfo(self.pid)?.op
        };

        match op {
            SyscallInfoOp::Entry { .. } => (),
            SyscallInfoOp::Exit { .. } => {
                // never restart old syscalls on exit
                restart_child_old_syscall = false;
                restart_parent_old_syscall = false;

                // handle syscall exit
                debug_assert_eq!(
                    self.instr_at(
                        saved_regs.ip() as usize - instructions::SYSCALL.length(),
                        instructions::SYSCALL.length()
                    ),
                    instructions::SYSCALL
                );

                self.write_registers(
                    saved_regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize)),
                )?; // jump back to previous syscall

                ptrace::syscall(self.pid, None)?;

                assert_eq!(
                    waitpid(self.pid, None)?,
                    WaitStatus::PtraceSyscall(self.pid)
                );

                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    SyscallInfoOp::Entry { .. }
                ));
            }
            SyscallInfoOp::None => {
                // insert an ad-hoc syscall instruction
                restart_child_old_syscall = false;
                restart_parent_old_syscall = false;

                saved_instr = Some(self.instr_inject(instructions::SYSCALL)?);

                ptrace::syscall(self.pid, None)?;

                assert_eq!(
                    waitpid(self.pid, None)?,
                    WaitStatus::PtraceSyscall(self.pid)
                );

                debug_assert!(matches!(
                    ptrace::getsyscallinfo(self.pid)?.op,
                    SyscallInfoOp::Entry { .. }
                ));
            }
            _ => panic!(),
        };

        // prepare the injected syscall number and arguments
        self.write_registers(saved_regs.with_sysno(nr).with_syscall_args(args))?;

        // block signals during our injected syscall
        ptrace::setsigmask(self.pid, !0)?;

        // execute our injected syscall
        ptrace::syscall(self.pid, None)?;

        // expect the syscall event
        let mut wait_status = waitpid(self.pid, None)?;

        // handle fork/clone event
        let child_pid = if let WaitStatus::PtraceEvent(pid, _sig, event) = wait_status {
            let child_pid = Pid::from_raw(match event {
                nix::libc::PTRACE_EVENT_CLONE | nix::libc::PTRACE_EVENT_FORK => {
                    ptrace::getevent(pid)? as _
                }
                _ => panic!("Unexpected ptrace event received"),
            });

            ptrace::syscall(self.pid, None)?;
            wait_status = waitpid(self.pid, None)?;
            Some(child_pid)
        } else {
            None
        };

        assert_eq!(wait_status, WaitStatus::PtraceSyscall(self.pid));

        // get the syscall return value
        let syscall_info = ptrace::getsyscallinfo(self.pid)?;
        let syscall_ret = if let SyscallInfoOp::Exit { ret_val, .. } = syscall_info.op {
            ret_val
        } else {
            panic!("Unexpected syscall info: {:?}", syscall_info);
        };

        Self::restore_state(
            self.pid,
            saved_regs,
            saved_sigmask,
            restart_parent_old_syscall,
            saved_instr,
        )?;

        if let Some(child_pid) = child_pid {
            let wait_status = waitpid(child_pid, None)?;
            assert!(
                matches!(wait_status, WaitStatus::PtraceEvent(pid, sig, _ev) if pid == child_pid && sig == Signal::SIGTRAP)
            );

            Self::restore_state(
                child_pid,
                saved_regs,
                saved_sigmask,
                restart_child_old_syscall,
                saved_instr,
            )?;
        }

        Ok(syscall_ret)
    }

    pub fn clone_process(
        &self,
        flags: CloneFlags,
        signal: Option<Signal>,
        restart_parent_old_syscall: bool,
        restart_child_old_syscall: bool,
    ) -> Result<Process> {
        let clone_flags: usize = flags.bits() as usize | signal.map_or(0, |x| x as usize);

        let child_pid = self.syscall_direct(
            Sysno::clone,
            syscall_args!(clone_flags, 0, 0, 0, 0),
            restart_parent_old_syscall,
            restart_child_old_syscall,
            false,
        )?;

        if child_pid <= 0 {
            panic!("Unexpected pid returned from clone: {}", child_pid);
        }

        let child = Process::new(Pid::from_raw(child_pid as _));

        Ok(child)
    }

    fn save_state(pid: Pid) -> Result<(Registers, u64)> {
        Ok((
            Process::new(pid).read_registers_precise()?,
            ptrace::getsigmask(pid)?,
        ))
    }

    fn restore_state(
        pid: Pid,
        saved_regs: Registers,
        saved_sigmask: u64,
        restart_old_syscall: bool,
        saved_instr: Option<InjectedInstructionContext>,
    ) -> Result<()> {
        let process = Process::new(pid);
        let mut saved_regs = saved_regs;

        if restart_old_syscall {
            assert!(saved_instr.is_none());

            // jump back to the previous instruction
            debug_assert_eq!(
                process.instr_at(
                    saved_regs.ip() - instructions::SYSCALL.length(),
                    instructions::SYSCALL.length()
                ),
                instructions::SYSCALL
            );
            saved_regs = saved_regs.with_offsetted_ip(-(instructions::SYSCALL.length() as isize));

            #[cfg(target_arch = "x86_64")]
            {
                saved_regs.inner.rax = saved_regs.inner.orig_rax;
            }
        }

        // restore the registers
        process.write_registers(saved_regs)?;

        if let Some(saved_instr) = saved_instr {
            process.instr_restore(saved_instr)?;
        }

        if restart_old_syscall {
            // execute the original syscall
            ptrace::syscall(pid, None)?;

            // expect the syscall event
            // TODO: handle death
            let wait_status = waitpid(pid, None)?;
            assert_eq!(wait_status, WaitStatus::PtraceSyscall(pid));

            if cfg!(debug_assertions) {
                // expect the syscall nr
                let syscall_info = ptrace::getsyscallinfo(pid)?;

                let orig_nr = saved_regs.sysno_raw();

                assert!(
                    matches!(syscall_info.op, SyscallInfoOp::Entry { nr, .. } if nr == orig_nr as _)
                );
            }
        }

        // restore the signal mask
        ptrace::setsigmask(pid, saved_sigmask)?;

        Ok(())
    }
}

#[cfg(test)]
pub(crate) mod tests {
    use nix::{
        sys::{
            signal::{kill, raise, Signal::SIGKILL},
            wait::WaitPidFlag,
        },
        unistd::{fork, getpid, gettid, getuid, ForkResult},
    };

    use super::super::OwnedProcess;
    use super::*;

    pub fn trace(f: impl FnOnce() -> i32) -> OwnedProcess {
        match unsafe { fork().unwrap() } {
            ForkResult::Parent { child } => {
                let wait_status = waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();
                assert_eq!(wait_status, WaitStatus::Stopped(child, Signal::SIGSTOP));
                ptrace::seize(
                    child,
                    ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEFORK
                        | ptrace::Options::PTRACE_O_EXITKILL,
                )
                .unwrap();
                OwnedProcess::new(child)
            }
            ForkResult::Child => {
                raise(Signal::SIGSTOP).unwrap();
                let code = f();
                std::process::exit(code)
            }
        }
    }

    #[test]

    fn test_process_syscall_injection_on_entry() {
        let process = trace(|| {
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

        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Stopped(process.pid, Signal::SIGSTOP)
        );

        // second getpid entry
        ptrace::syscall(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(process.pid)
        );

        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        // inject a getuid syscall
        let uid2 = process
            .syscall_direct(Sysno::getuid, syscall_args!(), true, true, false)
            .unwrap();

        assert_eq!(uid.as_raw(), uid2 as u32);

        // second getpid exit
        ptrace::syscall(process.pid, None).unwrap();
        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(process.pid)
        );

        dbg!(ptrace::getsyscallinfo(process.pid).unwrap());

        // gettid entry
        ptrace::syscall(process.pid, None).unwrap();
        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(process.pid)
        );
        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // program exit
        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Exited(process.pid, 0)
        );
    }

    #[test]

    fn test_process_syscall_injection_on_exit() {
        let process = trace(|| {
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

        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Stopped(process.pid, Signal::SIGSTOP)
        );

        // second getpid entry
        ptrace::syscall(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(process.pid)
        );

        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        // second getpid exit
        ptrace::syscall(process.pid, None).unwrap();
        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(process.pid)
        );

        // inject a getuid syscall
        let uid2 = process
            .syscall_direct(Sysno::getuid, syscall_args!(), true, true, false)
            .unwrap();
        assert_eq!(uid.as_raw(), uid2 as u32);

        // gettid entry
        ptrace::syscall(process.pid, None).unwrap();
        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(process.pid)
        );
        assert_eq!(
            process.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // program exit
        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Exited(process.pid, 0)
        );
    }

    #[test]

    fn test_process_syscall_injection_on_exit_with_clone() {
        let parent = trace(|| {
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

        ptrace::cont(parent.pid, None).unwrap();

        assert_eq!(
            parent.waitpid().unwrap(),
            WaitStatus::Stopped(parent.pid, Signal::SIGSTOP)
        );

        // second getpid entry
        ptrace::syscall(parent.pid, None).unwrap();

        assert_eq!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(parent.pid)
        );

        assert_eq!(
            parent.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        // second getpid exit
        ptrace::syscall(parent.pid, None).unwrap();
        assert_eq!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(parent.pid)
        );

        // clone the process
        let child = parent
            .clone_process(CloneFlags::CLONE_PARENT, None, false, false)
            .unwrap()
            .as_owned();

        // parent gettid entry
        ptrace::syscall(parent.pid, None).unwrap();
        assert_eq!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(parent.pid)
        );
        assert_eq!(
            parent.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // parent exit
        ptrace::cont(parent.pid, None).unwrap();
        assert_eq!(parent.waitpid().unwrap(), WaitStatus::Exited(parent.pid, 0));

        // child gettid entry
        ptrace::syscall(child.pid, None).unwrap();
        assert_eq!(
            child.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(child.pid)
        );
        assert_eq!(
            child.read_registers().unwrap().sysno().unwrap(),
            Sysno::gettid
        );

        // child exit
        ptrace::cont(child.pid, None).unwrap();
        assert_eq!(child.waitpid().unwrap(), WaitStatus::Exited(child.pid, 0));
    }

    #[test]

    fn test_process_clone() {
        let parent = trace(|| {
            // syscall is injected here
            getpid();

            0
        });

        // getpid entry
        ptrace::syscall(parent.pid, None).unwrap();

        assert_eq!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(parent.pid)
        );

        assert_eq!(
            parent.read_registers().unwrap().sysno().unwrap(),
            Sysno::getpid
        );

        assert!(matches!(
            ptrace::getsyscallinfo(parent.pid).unwrap().op,
            SyscallInfoOp::Entry { .. }
        ));

        let mut regs = parent.read_registers().unwrap();

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

        parent.write_registers(regs).unwrap();

        // clone the process
        let child = parent
            .clone_process(CloneFlags::CLONE_PARENT, None, false, false)
            .unwrap()
            .as_owned();

        assert!(matches!(
            ptrace::getsyscallinfo(parent.pid).unwrap().op,
            SyscallInfoOp::Exit { .. }
        ));

        #[cfg(target_arch = "aarch64")]
        {
            assert_eq!(parent.read_registers_precise().unwrap().with_x7(0), regs);
            assert_eq!(child.read_registers().unwrap().with_x7(0), regs);
        }
        #[cfg(not(target_arch = "aarch64"))]
        {
            assert_eq!(parent.read_registers_precise().unwrap(), regs);
            assert_eq!(child.read_registers().unwrap(), regs);
        }

        kill(parent.pid, SIGKILL).unwrap();
        assert!(matches!(
            parent.waitpid().unwrap(),
            WaitStatus::Signaled(_, _, _)
        ));

        kill(child.pid, SIGKILL).unwrap();
        assert!(matches!(
            child.waitpid().unwrap(),
            WaitStatus::Signaled(_, _, _)
        ));
    }
}
