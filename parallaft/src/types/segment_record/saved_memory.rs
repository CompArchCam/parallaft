use std::io::{IoSlice, IoSliceMut};

use nix::sys::uio::RemoteIoVec;
use reverie_syscalls::MemoryAccess;

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
        let mut buf: Vec<u8> = vec![0; iovecs.iter().map(|&iov| iov.len).sum()];

        memory.read_vectored(
            &iovecs
                .iter()
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
                .iter()
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
