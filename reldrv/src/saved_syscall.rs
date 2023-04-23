use std::io::{IoSlice, IoSliceMut};

use nix::sys::uio::RemoteIoVec;
use reverie_syscalls::{MemoryAccess, Syscall};

#[derive(Debug)]
pub struct SavedMemory {
    iovecs: Box<[RemoteIoVec]>,
    buf: Box<[u8]>,
}

impl SavedMemory {
    pub fn save<M: MemoryAccess>(
        memory: &M,
        iovecs: &[RemoteIoVec],
    ) -> Result<Self, reverie_syscalls::Errno> {
        let mut buf: Vec<u8> = vec![0; iovecs.into_iter().map(|&iov| iov.len).sum()];

        memory.read_vectored(
            &iovecs
                .into_iter()
                .map(|&iov| {
                    IoSlice::new(unsafe { ::std::slice::from_raw_parts(iov.base as _, iov.len) })
                })
                .collect::<Vec<IoSlice>>(),
            &mut [IoSliceMut::new(buf.as_mut_slice())],
        )?;

        Ok(SavedMemory {
            iovecs: Vec::from(iovecs).into_boxed_slice(),
            buf: buf.into_boxed_slice(),
        })
    }

    pub fn compare<M: MemoryAccess>(&self, memory: &M) -> Result<bool, reverie_syscalls::Errno> {
        let buf = Self::save(memory, &self.iovecs)?.buf;
        Ok(buf == self.buf)
    }

    pub fn dump<M: MemoryAccess>(&self, memory: &mut M) -> Result<(), reverie_syscalls::Errno> {
        memory.write_vectored(
            &[IoSlice::new(&self.buf)],
            &mut self
                .iovecs
                .into_iter()
                .map(|iov| {
                    IoSliceMut::new(unsafe {
                        ::std::slice::from_raw_parts_mut(iov.base as _, iov.len)
                    })
                })
                .collect::<Vec<IoSliceMut>>(),
        )?;

        Ok(())
    }
}

#[derive(Debug)]
pub enum SyscallExitAction {
    ReplicateMemoryWrites,
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
    pub fn upgrade(self, ret_val: isize, mem_write: Option<SavedMemory>) -> SavedSyscall {
        let new_kind = match self.kind {
            SavedIncompleteSyscallKind::KnownMemoryRAndWRange { mem_read, .. } => {
                SavedSyscallKind::KnownMemoryRw {
                    mem_read,
                    mem_written: mem_write.unwrap(),
                }
            }
            SavedIncompleteSyscallKind::UnknownMemoryRw => SavedSyscallKind::UnknownMemoryRw,
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
    UnknownMemoryRw, // or not needed
    KnownMemoryRAndWRange {
        mem_read: SavedMemory,
        mem_written_ranges: Box<[RemoteIoVec]>,
    },
}

#[derive(Debug)]
pub enum SavedSyscallKind {
    UnknownMemoryRw, // or not needed
    KnownMemoryRw {
        mem_read: SavedMemory,
        mem_written: SavedMemory,
    },
}

#[derive(Debug)]
pub struct SavedSyscall {
    // pub sysno: Sysno,
    // pub args: SyscallArgs,
    pub syscall: Syscall,
    pub ret_val: isize,
    pub kind: SavedSyscallKind,
    pub exit_action: SyscallExitAction,
}
