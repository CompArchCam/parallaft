//! Traits for getting address ranges that a syscall may read or write.

use reverie_memory::Addr;
use reverie_memory::AddrMut;
use reverie_memory::AddrSlice;
use reverie_memory::AddrSliceMut;
use reverie_memory::MemoryAccess;

use crate::Errno;
use crate::PathPtr;
use crate::ReadAddr;

/// A trait for getting address ranges that a syscall may read.
pub trait SyscallMayRead<'a, M: MemoryAccess> {
    /// Get the address ranges that may be read by the syscall.
    fn may_read(&'a self, _memory: &'a M) -> Result<Box<[AddrSlice<'a, u8>]>, Errno> {
        Ok(vec![].into_boxed_slice())
    }
}

/// Builder for constructing address ranges that a syscall may read.
pub struct RangesSyscallMayReadBuilder<'a, M: MemoryAccess> {
    ranges: Vec<AddrSlice<'a, u8>>,
    error: Option<Errno>,
    memory: &'a M,
}

impl<'a, M: MemoryAccess> RangesSyscallMayReadBuilder<'a, M> {
    /// Create a new builder.
    pub fn new(memory: &'a M) -> Self {
        Self {
            ranges: vec![],
            error: None,
            memory,
        }
    }

    fn set_error(&mut self) {
        self.error = Some(Errno::ENODATA);
    }

    /// Mark that the syscall may read anything in the memory.
    pub fn may_read_anything(mut self) -> Self {
        self.set_error();
        self
    }

    /// Add address ranges of a PathPtr that a syscall may read.
    pub fn may_read_path_ptr(mut self, path: Option<PathPtr<'a>>) -> Self {
        if self.error.is_some() {
            return self;
        }

        if let Some(path) = path {
            let ptr = path.into_inner();
            let addr = ptr.into_inner();
            if let Ok(c_str) = ptr.read(self.memory) {
                let len = c_str.into_bytes_with_nul().len();
                self.ranges
                    .push(unsafe { addr.into_addr_slice_with_len(len) });
            } else {
                self.set_error();
            }
        }
        self
    }

    /// Add address ranges of a buffer with specific length that a syscall may read.
    pub fn may_read_buf_with_len<T>(mut self, buf: Option<Addr<'a, T>>, len: usize) -> Self {
        if self.error.is_some() {
            return self;
        }

        if let Some(buf) = buf {
            self.ranges
                .push(unsafe { buf.into_addr_slice_with_len(len).as_addr_slice_u8() })
        }
        self
    }

    /// Add address ranges of an object that a syscall may read.
    pub fn may_read_object<T: 'a, A: Into<Addr<'a, T>>>(mut self, obj: Option<A>) -> Self {
        if self.error.is_some() {
            return self;
        }

        if let Some(obj) = obj {
            self.ranges
                .push(unsafe { obj.into().into_addr_slice().as_addr_slice_u8() })
        }
        self
    }

    /// Build the address ranges.
    pub fn build(self) -> Result<Box<[AddrSlice<'a, u8>]>, Errno> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(self.ranges.into_boxed_slice()),
        }
    }
}

/// A trait for getting address ranges that a syscall may write to.
pub trait SyscallMayWrite<'a, M: MemoryAccess> {
    /// Get the address ranges that may be written by the syscall.
    fn may_write(&'a self, _memory: &'a M) -> Result<Box<[AddrSliceMut<'a, u8>]>, Errno> {
        Ok(vec![].into_boxed_slice())
    }
}

/// Builder for constructing address ranges that a syscall may write.
pub struct RangesSyscallMayWriteBuilder<'a, M: MemoryAccess> {
    ranges: Vec<AddrSliceMut<'a, u8>>,
    error: Option<Errno>,
    _memory: &'a M,
}

impl<'a, M: MemoryAccess> RangesSyscallMayWriteBuilder<'a, M> {
    /// Create a new builder.
    pub fn new(memory: &'a M) -> Self {
        Self {
            ranges: vec![],
            error: None,
            _memory: memory,
        }
    }

    fn set_error(&mut self) {
        self.error = Some(Errno::ENODATA);
    }

    /// Mark that the syscall may write anything in the memory.
    pub fn may_write_anything(mut self) -> Self {
        self.set_error();
        self
    }

    /// Add address ranges of a buffer with specific length that a syscall may write.
    pub fn may_write_buf_with_len<T>(mut self, buf: Option<AddrMut<'a, T>>, len: usize) -> Self {
        if self.error.is_some() {
            return self;
        }

        if let Some(buf) = buf {
            self.ranges
                .push(unsafe { buf.into_addr_slice_mut_with_len(len).as_addr_slice_mut_u8() })
        }
        self
    }

    /// Add address ranges of an object that a syscall may write.
    pub fn may_write_object<T: 'a, A: Into<AddrMut<'a, T>>>(mut self, obj: Option<A>) -> Self {
        if self.error.is_some() {
            return self;
        }

        if let Some(obj) = obj {
            self.ranges
                .push(unsafe { obj.into().into_addr_slice_mut().as_addr_slice_mut_u8() })
        }
        self
    }

    /// Build the address ranges.
    pub fn build(self) -> Result<Box<[AddrSliceMut<'a, u8>]>, Errno> {
        match self.error {
            Some(err) => Err(err),
            None => Ok(self.ranges.into_boxed_slice()),
        }
    }
}

#[cfg(test)]
mod test {
    use crate::PathPtr;

    use super::RangesSyscallMayReadBuilder;
    use reverie_memory::LocalMemory;

    #[test]
    fn test_may_read_path_ptr() {
        let s = "hello\0";
        let p = PathPtr::from_ptr(s.as_ptr() as *const _);
        let memory = LocalMemory::new();
        let result = RangesSyscallMayReadBuilder::new(&memory)
            .may_read_path_ptr(p)
            .build();

        let result = result.unwrap();
        assert_eq!(result.len(), 1);
        assert_eq!(unsafe { result[0].as_ptr() }, s.as_ptr());
        assert_eq!(result[0].len(), s.len());
    }
}
