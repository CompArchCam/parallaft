use std::arch::x86_64::CpuidResult;
use std::fmt::Debug;
use std::ops::Deref;

#[cfg(feature = "compel")]
use compel::ParasiteCtl;

use lazy_init::Lazy;
use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
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
use reverie_syscalls::{Addr, MemoryAccess};
use syscalls::{syscall_args, SyscallArgs, Sysno};

use crate::{dirty_page_tracer::DirtyPageTracer, page_diff::page_diff};

pub struct Process {
    pub pid: Pid,
    dirty_page_tracer: Lazy<DirtyPageTracer>,
}

#[derive(Debug, Clone, Copy)]
pub struct Registers {
    pid: Pid,
    pub inner: user_regs_struct,
}

#[allow(unused)]
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
            self.inner.r10 = args.arg3 as _;
            self.inner.r8 = args.arg4 as _;
            self.inner.r9 = args.arg5 as _;
        } else {
            panic!("Unsupported architecture");
        }

        self
    }

    pub fn sysno(&self) -> Option<Sysno> {
        if cfg!(target_arch = "x86_64") {
            Sysno::new(self.sysno_raw())
        } else {
            panic!("Unsupported architecture")
        }
    }

    pub fn sysno_raw(&self) -> usize {
        if cfg!(target_arch = "x86_64") {
            self.inner.orig_rax as _
        } else {
            panic!("Unsupported architecture")
        }
    }

    pub fn syscall_args(&self) -> SyscallArgs {
        if cfg!(target_arch = "x86_64") {
            SyscallArgs::new(
                self.inner.rdi as _,
                self.inner.rsi as _,
                self.inner.rdx as _,
                self.inner.r10 as _,
                self.inner.r8 as _,
                self.inner.r9 as _,
            )
        } else {
            panic!("Unsupported architecture")
        }
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

    #[cfg(target_arch = "x86_64")]
    pub fn with_tsc(mut self, tsc: u64) -> Self {
        self.inner.rax = tsc & 0xffff_ffffu64;
        self.inner.rdx = tsc >> 32;

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_tscp(mut self, tsc: u64, aux: u32) -> Self {
        self.inner.rax = tsc & 0xffff_ffffu64;
        self.inner.rdx = tsc >> 32;
        self.inner.rcx = aux as _;

        self
    }

    pub fn with_offsetted_rip(mut self, offset: isize) -> Self {
        self.inner.rip = self.inner.rip.wrapping_add_signed(offset as _);

        self
    }

    #[cfg(target_arch = "x86_64")]
    pub fn with_cpuid_result(mut self, cpuid_result: CpuidResult) -> Self {
        self.inner.rax = cpuid_result.eax as _;
        self.inner.rbx = cpuid_result.ebx as _;
        self.inner.rcx = cpuid_result.ecx as _;
        self.inner.rdx = cpuid_result.edx as _;

        self
    }

    pub fn cpuid_leaf_subleaf(&self) -> (u32, u32) {
        (self.inner.rax as _, self.inner.rcx as _)
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
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            dirty_page_tracer: Lazy::new(),
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

    pub fn instr_at(&self, addr: usize, len: usize) -> usize {
        let val: usize = self.read_value(Addr::from_raw(addr).unwrap()).unwrap();

        val & ((1_usize << (len * 8)) - 1)
    }

    pub fn syscall_direct(
        &self,
        nr: Sysno,
        args: SyscallArgs,
        mut restart_parent_old_syscall: bool,
        mut restart_child_old_syscall: bool,
    ) -> i64 {
        let is_syscall_exit = match ptrace::getsyscallinfo(self.pid).unwrap().op {
            SyscallInfoOp::Entry { .. } => false,
            SyscallInfoOp::Exit { .. } => {
                // never restart old syscalls on exit
                restart_child_old_syscall = false;
                restart_parent_old_syscall = false;
                true
            }
            _ => panic!(),
        };

        // save the old states
        let (saved_regs, saved_sigmask) = Self::save_state(self.pid);

        // handle syscall exit
        if is_syscall_exit {
            assert_eq!(self.instr_at(saved_regs.inner.rip as usize - 2, 2), 0x050f); // syscall

            saved_regs.with_offsetted_rip(-2).write(); // jump back to previous syscall
            ptrace::syscall(self.pid, None).unwrap();

            assert!(matches!(
                waitpid(self.pid, None).unwrap(),
                WaitStatus::PtraceSyscall(_)
            ));

            assert!(matches!(
                ptrace::getsyscallinfo(self.pid).unwrap().op,
                SyscallInfoOp::Entry { .. }
            ));
        }

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
                assert_eq!(last_instr, 0x050f); // syscall
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

    fn dirty_page_tracer(&self) -> &DirtyPageTracer {
        self.dirty_page_tracer
            .get_or_create(|| DirtyPageTracer::new(self.pid.as_raw()))
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
        use_libcompel: bool,       // ignored if `compel` feature is disabled
        restart_old_syscall: bool, // restart parent's old syscall
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
                restart_old_syscall,
                true,
            )
        };

        #[cfg(not(feature = "compel"))]
        let child_pid = self.syscall_direct(
            Sysno::clone,
            syscall_args!(clone_flags, 0, 0, 0, 0),
            restart_old_syscall,
            true,
        );

        let child = Process::new(Pid::from_raw(child_pid as _));
        child
    }

    pub fn as_owned(self) -> OwnedProcess {
        OwnedProcess { inner: self }
    }

    pub fn waitpid(&self) -> Result<WaitStatus, Errno> {
        waitpid(self.pid, None)
    }
}

impl Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Process").field(&self.pid.as_raw()).finish()
    }
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

pub struct OwnedProcess {
    inner: Process,
}

impl OwnedProcess {
    pub fn new(pid: Pid) -> Self {
        Self {
            inner: Process::new(pid),
        }
    }
}

impl Deref for OwnedProcess {
    type Target = Process;

    fn deref(&self) -> &Self::Target {
        &self.inner
    }
}

impl Debug for OwnedProcess {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("OwnedProcess")
            .field(&self.pid.as_raw())
            .finish()
    }
}

impl Drop for OwnedProcess {
    fn drop(&mut self) {
        let result = kill(self.inner.pid, Signal::SIGKILL);

        // we don't need to reap zombie children here because they will be adpoted and reaped by PID 1 anyway after this process dies

        match result {
            Ok(_) | Err(Errno::ESRCH) => (),
            err => {
                panic!("Failed to kill process {:?}: {:?}", self.inner.pid, err);
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

#[cfg(test)]
mod tests {
    use nix::{
        sys::{signal::raise, wait::WaitPidFlag},
        unistd::{fork, getpid, gettid, getuid, ForkResult},
    };
    use serial_test::serial;

    use super::*;

    fn trace(f: impl FnOnce() -> i32) -> OwnedProcess {
        match unsafe { fork().unwrap() } {
            ForkResult::Parent { child } => {
                let wait_status = waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();
                assert_eq!(wait_status, WaitStatus::Stopped(child, Signal::SIGSTOP));
                ptrace::seize(
                    child,
                    ptrace::Options::PTRACE_O_TRACESYSGOOD
                        | ptrace::Options::PTRACE_O_TRACECLONE
                        | ptrace::Options::PTRACE_O_TRACEFORK,
                )
                .unwrap();
                // ptrace::setoptions(child, ptrace::Options::PTRACE_O_TRACESYSGOOD).unwrap();
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
    #[serial]
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

        assert!(matches!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));

        assert_eq!(process.registers().sysno().unwrap(), Sysno::getpid);

        // inject a getuid syscall
        let uid2 = process.syscall_direct(Sysno::getuid, syscall_args!(), true, true);

        assert_eq!(uid.as_raw(), uid2 as u32);

        // second getpid exit
        ptrace::syscall(process.pid, None).unwrap();
        assert!(matches!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));

        dbg!(ptrace::getsyscallinfo(process.pid).unwrap());

        // gettid entry
        ptrace::syscall(process.pid, None).unwrap();
        assert!(matches!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));
        assert_eq!(process.registers().sysno().unwrap(), Sysno::gettid);

        // program exit
        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Exited(process.pid, 0)
        );
    }

    #[test]
    #[serial]
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

        assert!(matches!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));

        assert_eq!(process.registers().sysno().unwrap(), Sysno::getpid);

        // second getpid exit
        ptrace::syscall(process.pid, None).unwrap();
        assert!(matches!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));

        // inject a getuid syscall
        let uid2 = process.syscall_direct(Sysno::getuid, syscall_args!(), true, true);
        assert_eq!(uid.as_raw(), uid2 as u32);

        // gettid entry
        ptrace::syscall(process.pid, None).unwrap();
        assert!(matches!(
            process.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));
        assert_eq!(process.registers().sysno().unwrap(), Sysno::gettid);

        // program exit
        ptrace::cont(process.pid, None).unwrap();

        assert_eq!(
            process.waitpid().unwrap(),
            WaitStatus::Exited(process.pid, 0)
        );
    }

    #[test]
    #[serial]
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

        assert!(matches!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));

        assert_eq!(parent.registers().sysno().unwrap(), Sysno::getpid);

        // second getpid exit
        ptrace::syscall(parent.pid, None).unwrap();
        assert!(matches!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));

        // clone the process
        let child = parent.clone_process(CloneFlags::CLONE_PARENT, None, false, false);

        // parent gettid entry
        ptrace::syscall(parent.pid, None).unwrap();
        assert!(matches!(
            parent.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));
        assert_eq!(parent.registers().sysno().unwrap(), Sysno::gettid);

        // parent exit
        ptrace::cont(parent.pid, None).unwrap();
        assert_eq!(parent.waitpid().unwrap(), WaitStatus::Exited(parent.pid, 0));

        // child gettid entry
        ptrace::syscall(child.pid, None).unwrap();
        assert!(matches!(
            child.waitpid().unwrap(),
            WaitStatus::PtraceSyscall(_)
        ));
        assert_eq!(child.registers().sysno().unwrap(), Sysno::gettid);

        // child exit
        ptrace::cont(child.pid, None).unwrap();
        assert_eq!(child.waitpid().unwrap(), WaitStatus::Exited(child.pid, 0));
    }
}
