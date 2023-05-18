use std::fmt::Debug;

#[cfg(feature = "compel")]
use compel::ParasiteCtl;

#[cfg(feature = "compel")]
use parasite::commands::{Request, Response};

#[cfg(feature = "compel")]
use log::debug;

use log::info;
use nix::libc::user_regs_struct;
use nix::{
    errno::Errno,
    sched::{sched_setaffinity, CloneFlags, CpuSet},
    sys::{
        ptrace::{self, SyscallInfoOp},
        signal::{kill, Signal},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use syscalls::{syscall_args, SyscallArgs, Sysno};

use parking_lot::{MappedMutexGuard, Mutex, MutexGuard};

use crate::{
    dirty_page_tracer::DirtyPageTracer, page_diff::page_diff, remote_memory::RemoteMemory,
};

pub struct Process {
    pub pid: Pid,
    tracer_pid: Pid,
    dirty_page_tracer: Mutex<Option<DirtyPageTracer>>,
    memory: Mutex<RemoteMemory>,
}

#[derive(Debug, Clone, Copy)]
pub struct Registers {
    pid: Pid,
    inner: user_regs_struct,
}

impl Registers {
    pub fn read_from(pid: Pid) -> Self {
        Self {
            pid,
            inner: ptrace::getregs(pid).unwrap(),
        }
    }

    pub fn with_sysno(mut self, nr: Sysno) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.inner.orig_rax = nr.id() as _;
            self.inner.rax = nr.id() as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    pub fn with_syscall_args(mut self, args: SyscallArgs) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.inner.rdi = args.arg0 as _;
            self.inner.rsi = args.arg1 as _;
            self.inner.rdx = args.arg2 as _;
            self.inner.rcx = args.arg3 as _;
            self.inner.r8 = args.arg4 as _;
            self.inner.r9 = args.arg5 as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    pub fn with_syscall_ret_val(mut self, ret_val: isize) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.inner.rax = ret_val as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    /// Skip the syscall by rewriting the current sysno to a nonexistent one.
    pub fn with_syscall_skipped(mut self) -> Self {
        if cfg!(target_arch = "x86_64") {
            self.inner.orig_rax = 0xff77 as _;
            self.inner.rax = 0xff77 as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    pub fn write(self) {
        ptrace::setregs(self.pid, self.inner).unwrap()
    }

    pub fn write_to(self, pid: Pid) {
        ptrace::setregs(pid, self.inner).unwrap()
    }
}

#[allow(unused)]
impl Process {
    pub fn new(pid: Pid, tracer_pid: Pid) -> Self {
        Self {
            pid,
            tracer_pid,
            dirty_page_tracer: Mutex::new(None),
            memory: Mutex::new(RemoteMemory::new(pid)),
        }
    }

    pub fn registers(&self) -> Registers {
        Registers::read_from(self.pid)
    }

    #[cfg(feature = "compel")]
    pub fn compel_prepare<T: Send + Copy, R: Send + Copy>(&self) -> ParasiteCtl<T, R> {
        compel::ParasiteCtl::<T, R>::prepare(self.pid.as_raw())
            .expect("failed to prepare parasite ctl")
    }

    #[cfg(feature = "compel")]
    pub fn syscall(&self, nr: Sysno, args: SyscallArgs) -> i64 {
        self.compel_prepare::<Request, Response>()
            .syscall(nr, args)
            .expect("failed to make remote syscall")
    }

    pub fn syscall_direct(
        &self,
        nr: Sysno,
        args: SyscallArgs,
        restart_parent_old_syscall: bool,
        restart_child_old_syscall: bool,
    ) -> i64 {
        assert!(matches!(
            ptrace::getsyscallinfo(self.pid).unwrap().op,
            SyscallInfoOp::Entry { .. }
        ));

        // save the old states
        let (saved_regs, saved_sigmask) = Self::save_state(self.pid);

        // prepare the injected syscall number and arguments
        saved_regs.with_sysno(nr).with_syscall_args(args).write();

        // block signals during our injected syscall
        ptrace::setsigmask(self.pid, !0).unwrap();

        // execute our injected syscall
        ptrace::syscall(self.pid, None).unwrap();

        // expect the syscall event
        let mut wait_status = waitpid(self.pid, None).unwrap();

        // handle fork/clone event
        let child_pid = if let WaitStatus::PtraceEvent(pid, sig, event) = wait_status {
            let child_pid = Pid::from_raw(match event {
                nix::libc::PTRACE_EVENT_CLONE | nix::libc::PTRACE_EVENT_FORK => {
                    ptrace::getevent(pid).unwrap() as _
                }
                _ => panic!("Unexpected ptrace event received"),
            });

            ptrace::syscall(self.pid, None).unwrap();
            wait_status = waitpid(self.pid, None).unwrap();
            Some(child_pid)
        } else {
            None
        };

        assert_eq!(wait_status, WaitStatus::PtraceSyscall(self.pid));

        // get the syscall return value
        let syscall_info = ptrace::getsyscallinfo(self.pid).unwrap();
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
        );

        if let Some(child_pid) = child_pid {
            let wait_status = waitpid(child_pid, None).unwrap();
            assert!(
                matches!(wait_status, WaitStatus::PtraceEvent(pid, sig, ev) if pid == child_pid && sig == Signal::SIGTRAP)
            );

            Self::restore_state(
                child_pid,
                saved_regs,
                saved_sigmask,
                restart_child_old_syscall,
            );
        }

        syscall_ret
    }

    fn save_state(pid: Pid) -> (Registers, u64) {
        (Registers::read_from(pid), ptrace::getsigmask(pid).unwrap())
    }

    fn restore_state(
        pid: Pid,
        saved_regs: Registers,
        saved_sigmask: u64,
        restart_old_syscall: bool,
    ) {
        let mut saved_regs = saved_regs;

        if restart_old_syscall {
            // jump back to the previous instruction
            if cfg!(target_arch = "x86_64") {
                let last_instr =
                    (ptrace::read(pid, (saved_regs.inner.rip - 2) as _).unwrap() as u64) & 0xffff;
                assert_eq!(last_instr, 0x050f);
                saved_regs.inner.rip -= 2;
                saved_regs.inner.rax = saved_regs.inner.orig_rax;
            } else {
                panic!("Unsupported architecture");
            }
        }

        // restore the registers
        saved_regs.write_to(pid);

        if restart_old_syscall {
            // execute the original syscall
            ptrace::syscall(pid, None).unwrap();

            // expect the syscall event
            // TODO: handle death
            let wait_status = waitpid(pid, None).unwrap();
            assert_eq!(wait_status, WaitStatus::PtraceSyscall(pid));

            // expect the syscall nr
            let syscall_info = ptrace::getsyscallinfo(pid).unwrap();

            let orig_nr = if cfg!(target_arch = "x86_64") {
                saved_regs.inner.orig_rax as usize
            } else {
                panic!("Unsupported architecture");
            };

            assert!(
                matches!(syscall_info.op, SyscallInfoOp::Entry { nr, .. } if nr == orig_nr as _)
            );
        }

        // restore the signal mask
        ptrace::setsigmask(pid, saved_sigmask).unwrap();
    }

    // pub fn syscall_replace(&self, nr: Sysno, args: SyscallArgs) -> i64 {
    //     // save the old states
    //     let mut saved_regs = ptrace::getregs(self.pid).unwrap();
    //     let saved_sigmask = ptrace::getsigmask(self.pid).unwrap();

    //     // prepare the injected syscall number and arguments
    //     let mut new_regs = saved_regs;

    //     if cfg!(target_arch = "x86_64") {
    //         new_regs.orig_rax = nr.id() as _;
    //         new_regs.rax = nr.id() as _;
    //         new_regs.rdi = args.arg0 as _;
    //         new_regs.rsi = args.arg1 as _;
    //         new_regs.rdx = args.arg2 as _;
    //         new_regs.rcx = args.arg3 as _;
    //         new_regs.r8 = args.arg4 as _;
    //         new_regs.r9 = args.arg5 as _;
    //     } else {
    //         panic!("Unsupported architecture");
    //     }

    //     ptrace::setregs(self.pid, new_regs).unwrap();

    //     // block signals during our injected syscall
    //     ptrace::setsigmask(self.pid, !0).unwrap();

    //     // execute our injected syscall
    //     ptrace::syscall(self.pid, None).unwrap();

    //     // expect the syscall event
    //     let wait_status = waitpid(self.pid, None).unwrap();
    //     assert_eq!(wait_status, WaitStatus::PtraceSyscall(self.pid));

    //     // get the syscall return value
    //     let syscall_info = ptrace::getsyscallinfo(self.pid).unwrap();
    //     let syscall_ret = if let SyscallInfoOp::Exit { ret_val, .. } = syscall_info.op {
    //         ret_val
    //     } else {
    //         panic!("Unexpected syscall info: {:?}", syscall_info);
    //     };

    //     // restore the registers
    //     ptrace::setregs(self.pid, saved_regs).unwrap();

    //     // restore the signal mask
    //     ptrace::setsigmask(self.pid, saved_sigmask).unwrap();

    //     syscall_ret
    // }

    pub fn dirty_page_delta_against(
        &self,
        other: &Process,
        ignored_pages: &[u64],
    ) -> (bool, usize) {
        let dirty_pages_myself: Vec<u64> = self
            .get_dirty_pages()
            .into_iter()
            .filter(|addr| !ignored_pages.contains(addr))
            .collect();

        let dirty_pages_other: Vec<u64> = other
            .get_dirty_pages()
            .into_iter()
            .filter(|addr| !ignored_pages.contains(addr))
            .collect();

        info!("{} dirty pages", dirty_pages_myself.len());
        let result =
            page_diff(self.pid, other.pid, &dirty_pages_myself, &dirty_pages_other).unwrap();

        match result {
            crate::page_diff::PageDiffResult::Equal => (true, dirty_pages_myself.len()),
            _ => (false, dirty_pages_myself.len()),
        }
    }

    fn dirty_page_tracer(&self) -> MappedMutexGuard<DirtyPageTracer> {
        MutexGuard::map(self.dirty_page_tracer.lock(), |t| {
            t.get_or_insert_with(|| DirtyPageTracer::new(self.pid.as_raw()))
        })
    }

    pub fn clear_dirty_page_bits(&self) {
        self.dirty_page_tracer().clear_dirty_bits();
    }

    pub fn get_dirty_pages(&self) -> Vec<u64> {
        self.dirty_page_tracer().get_dirty_pages()
    }

    pub fn resume(&self) {
        ptrace::syscall(self.pid, None).unwrap();
    }

    pub fn interrupt(&self) {
        ptrace::interrupt(self.pid).unwrap();
    }

    pub fn set_cpu_affinity(&self, cpus: &Vec<usize>) {
        if !cpus.is_empty() {
            let mut cpuset = CpuSet::new();
            for cpu in cpus {
                cpuset.set(*cpu).unwrap();
            }
            sched_setaffinity(self.pid, &cpuset).unwrap();
        }
    }

    pub fn clone_process(
        &self,
        flags: CloneFlags,
        signal: Option<Signal>,
        use_libcompel: bool, // ignored if `compel` feature is disabled
    ) -> Process {
        let clone_flags: usize = flags.bits() as usize | signal.map_or(0, |x| x as usize);

        #[cfg(feature = "compel")]
        let child_pid = if use_libcompel {
            debug!("Using libcompel for syscall injection");
            self.syscall(Sysno::clone, syscall_args!(clone_flags, 0, 0, 0, 0))
        } else {
            debug!("Using ptrace for syscall injection");
            self.syscall_direct(
                Sysno::clone,
                syscall_args!(clone_flags, 0, 0, 0, 0),
                false,
                true,
            )
        };

        #[cfg(not(feature = "compel"))]
        let child_pid = self.syscall_direct(
            Sysno::clone,
            syscall_args!(clone_flags, 0, 0, 0, 0),
            false,
            true,
        );

        let child = Process::new(Pid::from_raw(child_pid as _), self.tracer_pid);
        child
    }

    pub fn memory(&self) -> MutexGuard<RemoteMemory> {
        self.memory.lock()
    }

    // pub fn memory_mut(&self) -> RefMut<RemoteMemory> {
    //     self.memory.borrow_mut()
    // }
}

impl Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Process").field(&self.pid.as_raw()).finish()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let result = kill(self.pid, Signal::SIGKILL);

        // we don't need to reap zombie children here because they will be adpoted and reaped by PID 1 anyway after this process dies

        match result {
            Ok(_) | Err(Errno::ESRCH) => (),
            err => {
                panic!("Failed to kill process {:?}: {:?}", self.pid, err);
            }
        }
    }
}

// struct ProcessMap {
//     inner: HashMap<Pid, Weak<Process>>,
// }

// impl ProcessMap {
//     pub fn new() -> Self {
//         Self {
//             inner: HashMap::new(),
//         }
//     }

//     pub fn add_process(&mut self, process: Rc<Process>) {
//         self.inner.insert(process.pid, Rc::downgrade(&process));
//     }

//     pub fn find_process_by_pid(&mut self, pid: Pid) -> Option<Rc<Process>> {
//         self.inner.get(&pid).and_then(|process| {
//             process.upgrade().or_else(|| {
//                 self.inner.remove(&pid);
//                 None
//             })
//         })
//     }

//     pub fn cleanup(&mut self) {
//         self.inner.retain(|pid, process| process.strong_count() > 0)
//     }
// }
