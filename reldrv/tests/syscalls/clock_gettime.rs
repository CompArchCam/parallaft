use std::mem::MaybeUninit;

use crate::common::{checkpoint_fini, checkpoint_take, trace};
use nix::libc;

#[test]
fn clock_gettime() {
    trace(|| {
        checkpoint_take();
        let mut t = MaybeUninit::<libc::timespec>::uninit();

        unsafe {
            libc::syscall(
                libc::SYS_clock_gettime,
                libc::CLOCK_MONOTONIC,
                t.as_mut_ptr(),
            )
        };

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}
