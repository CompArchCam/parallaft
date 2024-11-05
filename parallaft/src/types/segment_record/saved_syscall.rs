use nix::sys::uio::RemoteIoVec;
use reverie_syscalls::Syscall;

use super::saved_memory::SavedMemory;

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum SyscallExitAction {
    ReplayEffects,
    ReplicateSyscall,
    Checkpoint,
    Custom,
}

#[derive(Debug)]
pub struct SavedIncompleteSyscall {
    pub syscall: Syscall,
    pub kind: SavedIncompleteSyscallKind,
    pub exit_action: SyscallExitAction,
}

impl SavedIncompleteSyscall {
    pub fn with_return_value(self, ret_val: isize, mem_write: Option<SavedMemory>) -> SavedSyscall {
        let new_kind = match self.kind {
            SavedIncompleteSyscallKind::WithMemoryEffects { mem_read, .. } => {
                SavedSyscallKind::WithMemoryEffects {
                    mem_read,
                    mem_written: mem_write.unwrap(),
                }
            }
            SavedIncompleteSyscallKind::WithoutMemoryEffects => {
                SavedSyscallKind::WithoutMemoryEffects
            }
        };

        SavedSyscall {
            // sysno: self.sysno,
            // args: self.args,
            syscall: self.syscall,
            ret_val,
            kind: new_kind,
            exit_action: self.exit_action,
        }
    }
}

#[derive(Debug)]
pub enum SavedIncompleteSyscallKind {
    WithoutMemoryEffects, // or not needed
    WithMemoryEffects {
        mem_read: SavedMemory,
        mem_written_ranges: Box<[RemoteIoVec]>,
    },
}

#[derive(Debug)]
pub enum SavedSyscallKind {
    WithoutMemoryEffects,
    WithMemoryEffects {
        mem_read: SavedMemory,
        mem_written: SavedMemory,
    },
}

#[derive(Debug)]
pub struct SavedSyscall {
    pub syscall: Syscall,
    pub ret_val: isize,
    pub kind: SavedSyscallKind,
    pub exit_action: SyscallExitAction,
}
