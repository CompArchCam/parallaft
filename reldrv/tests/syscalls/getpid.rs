use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};
use nix::libc;
use serial_test::serial;

#[test]
#[serial]
fn getpid_loop() {
    setup();
    assert_eq!(
        trace(|| {
            let orig_pid = unsafe { libc::getpid() };

            checkpoint_take();

            for _ in 0..20 {
                let pid = unsafe { libc::getpid() };
                assert_eq!(pid, orig_pid);
            }

            checkpoint_fini();
            0
        }),
        0
    );
}

#[test]
#[serial]
fn checkpoint_getpid_loop() {
    setup();
    assert_eq!(
        trace(|| {
            let orig_pid = unsafe { libc::getpid() };

            for _ in 0..200 {
                checkpoint_take();
                let pid = unsafe { libc::getpid() };
                assert_eq!(pid, orig_pid);
            }

            checkpoint_fini();
            0
        }),
        0
    );
}
