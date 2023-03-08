use std::{
    cell::{RefCell, RefMut},
    collections::HashSet,
    fmt::Debug,
    rc::Rc,
};

use compel::{
    syscalls::{syscall_args, SyscallArgs, Sysno},
    ParasiteCtl,
};
use log::{debug, info};
use nix::{
    errno::Errno,
    sched::{sched_setaffinity, CpuSet},
    sys::{
        ptrace,
        signal::{kill, Signal},
    },
    unistd::Pid,
};
use parasite::commands::{Request, Response};

use crate::{dirty_page_tracer::DirtyPageTracer, page_diff::page_diff};

pub struct Process {
    pub pid: Pid,
    pub parent: Option<Rc<Process>>,
    pub zombie_children: RefCell<HashSet<Pid>>,

    dirty_page_tracer: RefCell<Option<DirtyPageTracer>>,
}

pub trait ProcessCloneExt {
    fn clone_process(&self) -> Rc<Process>;
}

impl ProcessCloneExt for Rc<Process> {
    fn clone_process(&self) -> Rc<Process> {
        let parent = self.clone();
        let child_pid = self.syscall(Sysno::clone, syscall_args!(libc::SIGCHLD as _, 0, 0, 0, 0));
        let child = Process::new(Pid::from_raw(child_pid as _), Some(parent));
        Rc::new(child)
    }
}

#[allow(unused)]
impl Process {
    pub fn new(pid: Pid, parent: Option<Rc<Process>>) -> Self {
        Self {
            pid,
            dirty_page_tracer: RefCell::new(None),
            parent,
            zombie_children: RefCell::new(HashSet::new()),
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

    pub fn waitpid(&self, pid: Pid) -> Result<bool, Errno> {
        let result = self.syscall(
            Sysno::wait4,
            syscall_args!(pid.as_raw() as _, 0, libc::WNOHANG as _, 0),
        );
        if result < 0 {
            Err(Errno::from_i32(-result as _))
        } else {
            Ok(result > 0)
        }
    }

    pub fn reap_zombie_children(&self) {
        let mut zombie_children = self.zombie_children.borrow_mut();
        let mut parasite_ctl = self.compel_prepare::<Request, Response>();

        for child_pid in zombie_children.iter() {
            info!("Reaping child {}", child_pid);
            let child_pid = *child_pid;
            let result = parasite_ctl
                .syscall(
                    Sysno::wait4,
                    syscall_args!(child_pid.as_raw() as _, 0, 0, 0),
                )
                .unwrap();
            debug!("wait4 result = {}", result);
        }

        zombie_children.clear();
    }

    pub fn reap_zombie_child(&self, pid: Pid) {
        let mut zombie_children = self.zombie_children.borrow_mut();
        zombie_children
            .take(&pid)
            .map(|_| self.waitpid(pid).unwrap())
            .unwrap();
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

    fn dirty_page_tracer(&self) -> RefMut<DirtyPageTracer> {
        RefMut::map(self.dirty_page_tracer.borrow_mut(), |x| {
            x.get_or_insert_with(|| DirtyPageTracer::new(self.pid.as_raw()))
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
}

impl Debug for Process {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_tuple("Process").field(&self.pid.as_raw()).finish()
    }
}

impl Drop for Process {
    fn drop(&mut self) {
        let pid = self.pid;
        if let Some(parent) = &self.parent {
            parent.zombie_children.borrow_mut().insert(pid);
        }

        let result = kill(pid, Signal::SIGKILL);

        // we don't need to reap zombie children here because they will be adpoted and reaped by PID 1 anyway after this process dies

        match result {
            Ok(_) | Err(Errno::ESRCH) => (),
            err => {
                panic!("Failed to kill process {:?}: {:?}", pid, err);
            }
        }
    }
}
