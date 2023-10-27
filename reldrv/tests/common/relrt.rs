use std::{arch::asm, marker::PhantomPinned, num::NonZeroUsize, os::fd::OwnedFd};

use nix::{libc, sys::mman};
use reldrv::{inferior_rtlib::relrtlib::SYSNO_SET_COUNTER_ADDR, process::PAGESIZE};

pub struct RelRt {
    counter_addr: *mut u64,
    _marker: PhantomPinned,
}

impl RelRt {
    pub fn new() -> Self {
        let addr = unsafe {
            mman::mmap::<OwnedFd>(
                None,
                NonZeroUsize::new_unchecked(*PAGESIZE as _),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_PRIVATE | mman::MapFlags::MAP_ANONYMOUS,
                None,
                0,
            )
            .unwrap()
        };

        Self {
            counter_addr: addr as _,
            _marker: PhantomPinned,
        }
    }

    pub fn enable(&mut self) {
        unsafe { libc::syscall(SYSNO_SET_COUNTER_ADDR as _, self.counter_addr) };
    }

    pub fn try_yield(&mut self) {
        unsafe {
            asm!(
                "
                        add dword ptr [{0}], 1
                        jnc 1f
                        mov rax, 0xff77
                        syscall
                        1:
                    ",
                in(reg) self.counter_addr,
                out("rcx") _,
                out("r11") _,
                out("rax") _,
            )
        }
    }
}
