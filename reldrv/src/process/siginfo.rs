use nix::{
    libc::{self, siginfo_t},
    sys::ptrace,
};

use crate::error::Result;

use super::Process;

impl Process {
    pub fn get_siginfo(&self) -> Result<siginfo_t> {
        Ok(ptrace::getsiginfo(self.pid)?)
    }
}

pub trait SigInfoExt {
    fn is_trap(&self) -> bool;
    fn is_trap_bp(&self) -> bool;
    fn is_trap_hwbp(&self) -> bool;
    fn is_trap_trace(&self) -> bool;
    fn sigval(&self) -> Option<usize>;
}

impl SigInfoExt for siginfo_t {
    fn is_trap(&self) -> bool {
        self.si_signo == libc::SIGTRAP
    }

    fn is_trap_bp(&self) -> bool {
        self.is_trap() && self.si_code == 1 /* TRAP_BRKPT */
    }

    fn is_trap_hwbp(&self) -> bool {
        self.is_trap() && self.si_code == 4 /* TRAP_HWBKPT */
    }

    fn is_trap_trace(&self) -> bool {
        self.is_trap() && self.si_code == 2 /* TRAP_TRACE */
    }

    fn sigval(&self) -> Option<usize> {
        if self.si_signo == libc::SIGTRAP && self.si_code == -1
        /* SI_QUEUE */
        {
            return Some(unsafe { self.si_value().sival_ptr } as usize);
        } else {
            return None;
        }
    }
}
