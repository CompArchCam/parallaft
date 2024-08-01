pub mod clone;
pub mod execve;
pub mod exit;
pub mod mmap;
pub mod record_replay;
pub mod replicate;
pub mod rseq;

use reverie_syscalls::Syscall;

pub fn is_execve_ok(syscall: &Syscall, ret_val: isize) -> bool {
    matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) && ret_val == 0
}
