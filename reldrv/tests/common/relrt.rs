use std::{arch::asm, marker::PhantomPinned, num::NonZeroUsize, os::fd::OwnedFd};

use nix::{libc, sys::mman};
use reldrv::{process::PAGESIZE, types::custom_sysno::CustomSysno};

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
        unsafe { libc::syscall(CustomSysno::RelRtLibSetCounterAddr as _, self.counter_addr) };
    }

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "aarch64")]
    pub fn try_yield(&mut self) {
        unsafe {
            // TODO: this is not atomic
            asm!(
                "
                    ldr x0, [{0}]
                    add x0, x0, #1
                    str x0, [{0}]
                    bcc 1f
                    mov x8, #0xff77
                    svc #0
                1:
                ",
                in(reg) self.counter_addr,
                out("x0") _,
                out("x1") _,
                out("x8") _,
                out("x9") _,
                out("x10") _,
                out("x11") _,
                out("x12") _,
                out("x13") _,
                out("x14") _,
                out("x15") _,
            )
        }
    }
}
