use std::mem::MaybeUninit;

use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};
use nix::libc;
use serial_test::serial;

#[test]
#[serial]
fn clock_gettime() {
    setup();
    assert_eq!(
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
            0
        }),
        0
    )
}
