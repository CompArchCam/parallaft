use std::{num::NonZeroUsize, os::fd::OwnedFd, slice};

use crate::common::{
    checkpoint_take, relrt::RelRt, setup_trace_and_unwrap_with_options, RelShellOptions,
};
use nix::sys::mman;
use reldrv::process::PAGESIZE;
use serial_test::serial;

#[test]
#[serial]
fn limit() {
    setup_trace_and_unwrap_with_options::<(), reldrv::error::Error>(
        || {
            let size = (*PAGESIZE * 256) as usize;

            let addr = unsafe {
                mman::mmap::<OwnedFd>(
                    None,
                    NonZeroUsize::new_unchecked(size),
                    mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                    mman::MapFlags::MAP_PRIVATE | mman::MapFlags::MAP_ANONYMOUS,
                    None,
                    0,
                )?
            };

            dbg!(addr);

            let mut rt = RelRt::new();
            rt.enable();

            let buf = unsafe { slice::from_raw_parts_mut(addr as *mut u8, size) };

            checkpoint_take();

            for chunk in buf.chunks_mut(*PAGESIZE as usize) {
                rt.try_yield();
                chunk[0] = 0xde;
                chunk[1] = 0xad;
                chunk[2] = 0xbe;
                chunk[3] = 0xef;
            }

            unsafe { mman::munmap(addr, size)? };

            Ok(())
        },
        RelShellOptions::new().with_checkpoint_size_watermark(16),
    );

    // TODO: assert that >= 256 / 16 = 16 checkpoints have been taken
}
