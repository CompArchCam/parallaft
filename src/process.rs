use compel::{
    syscalls::{syscall_args, SyscallArgs, Sysno},
    ParasiteCtl,
};
use nix::{
    sched::{sched_setaffinity, CpuSet},
    sys::{
        ptrace,
        signal::{kill, Signal},
        wait::{waitpid, WaitStatus},
    },
    unistd::Pid,
};
use parasite::commands::{Request, Response};

use crate::{dirty_page_tracer::DirtyPageTracer, page_diff::page_diff};

#[derive(Debug)]
pub struct Process {
    pub pid: Pid,
    dirty_page_tracer: Option<DirtyPageTracer>,
}

impl Process {
    pub fn new(pid: Pid) -> Self {
        Self {
            pid,
            dirty_page_tracer: None,
        }
    }

    pub fn compel_prepare<T: Send + Copy, R: Send + Copy>(&self) -> ParasiteCtl<T, R> {
        compel::ParasiteCtl::<T, R>::prepare(self.pid.as_raw())
            .expect("failed to prepare parasite ctl")
    }

    pub fn syscall(&self, nr: Sysno, args: SyscallArgs) -> i64 {
        self.compel_prepare::<Request, Response>()
            .syscall(nr, args)
            .expect("failed to make remote syscall")
    }

    pub fn fork(&self) -> Process {
        let result = self.syscall(Sysno::clone, syscall_args!(libc::SIGCHLD as _, 0, 0, 0, 0));

        Process::new(Pid::from_raw(result as _))
    }

    pub fn waitpid(&self, pid: Pid) {
        self.syscall(Sysno::wait4, syscall_args!(pid.as_raw() as _, 0, 0, 0));
    }

    pub fn dirty_page_delta_against(&self, other: &Process) -> bool {
        let dirty_pages_myself = self.get_dirty_pages();
        let dirty_pages_other = other.get_dirty_pages();
        let result =
            page_diff(self.pid, other.pid, &dirty_pages_myself, &dirty_pages_other).unwrap();

        match result {
            crate::page_diff::PageDiffResult::Equal => true,
            _ => false,
        }
    }

    pub fn clear_dirty_page_bits(&mut self) {
        let tracer = self
            .dirty_page_tracer
            .get_or_insert_with(|| DirtyPageTracer::new(self.pid.as_raw()));
        tracer.clear_dirty_bits();
    }

    pub fn get_dirty_pages(&self) -> Vec<u64> {
        self.dirty_page_tracer.as_ref().unwrap().get_dirty_pages()
    }

    pub fn resume(&self) {
        ptrace::syscall(self.pid, None).unwrap();
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
}

impl Drop for Process {
    fn drop(&mut self) {
        let pid = self.pid;

        kill(pid, Signal::SIGKILL).unwrap();
        let status = waitpid(pid, None).unwrap();
        assert!(matches!(
            status,
            WaitStatus::Signaled(p, Signal::SIGKILL, false) if p == pid
        ));
    }
}
