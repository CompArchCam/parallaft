//! Traits for speculating the result of a syscall.

use reverie_memory::MemoryAccess;

/// A trait for speculating the result of a syscall.
pub trait SyscallSpeculate<'a, M: MemoryAccess> {
    /// Predict the return value of the syscall.
    fn speculate(&'a self, _memory: &'a M) -> Option<isize> {
        None
    }
}
