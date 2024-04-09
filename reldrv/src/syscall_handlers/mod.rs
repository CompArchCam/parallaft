pub mod clone;
pub mod execve;
pub mod exit;
pub mod mmap;
pub mod record_replay;
pub mod replicate;
pub mod rseq;

use reverie_syscalls::Syscall;

pub const SYSNO_CHECKPOINT_TAKE: usize = 0xff77;
pub const SYSNO_CHECKPOINT_FINI: usize = 0xff78;
pub const SYSNO_CHECKPOINT_SYNC: usize = 0xff79;
pub const CUSTOM_SYSNO_START: usize = 0xff7a;

pub fn is_execve_ok(syscall: &Syscall, ret_val: isize) -> bool {
    return matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) && ret_val == 0;
}
