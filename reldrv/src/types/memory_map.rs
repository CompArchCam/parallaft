use std::ffi::c_void;

use procfs::process::MMPermissions;
use reverie_syscalls::{FromToRaw, MapFlags, Mmap, Munmap, ProtFlags};

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MemoryMap {
    pub start: usize,
    pub len: usize,
    pub perms: MMPermissions,
}

impl MemoryMap {
    pub fn from_mmap(mmap: &Mmap, ret_val: isize) -> Option<Self> {
        if ret_val as *mut c_void == nix::libc::MAP_FAILED {
            return None;
        }

        let mut perms = MMPermissions::empty();

        perms.set(
            MMPermissions::READ,
            mmap.prot().contains(ProtFlags::PROT_READ),
        );

        perms.set(
            MMPermissions::WRITE,
            mmap.prot().contains(ProtFlags::PROT_WRITE),
        );

        perms.set(
            MMPermissions::EXECUTE,
            mmap.prot().contains(ProtFlags::PROT_EXEC),
        );

        perms.set(
            MMPermissions::PRIVATE,
            mmap.flags().contains(MapFlags::MAP_PRIVATE),
        );

        perms.set(
            MMPermissions::SHARED,
            mmap.flags().contains(MapFlags::MAP_SHARED),
        );

        Some(MemoryMap {
            start: ret_val as usize,
            len: mmap.len(),
            perms,
        })
    }

    pub fn from_munmap(munmap: &Munmap, ret_val: isize) -> Option<Self> {
        if ret_val != 0 {
            return None;
        }

        Some(MemoryMap {
            start: munmap.addr().into_raw(),
            len: munmap.len(),
            perms: MMPermissions::empty(),
        })
    }

    pub fn all() -> Self {
        MemoryMap {
            start: 0,
            len: usize::MAX,
            perms: MMPermissions::empty(),
        }
    }
}

impl From<procfs::process::MemoryMap> for MemoryMap {
    fn from(value: procfs::process::MemoryMap) -> Self {
        Self {
            start: value.address.0 as _,
            len: (value.address.1 - value.address.0) as _,
            perms: value.perms,
        }
    }
}
