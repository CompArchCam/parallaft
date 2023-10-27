use crate::common::{checkpoint_take, setup, trace};
use nix::libc;
use serial_test::serial;

#[test]
#[serial]
fn exit() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            unsafe { libc::syscall(libc::SYS_exit, 42) };
            unreachable!()
        }),
        42
    );
}

#[test]
#[serial]
fn exit_group() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            unsafe { libc::syscall(libc::SYS_exit_group, 42) };
            unreachable!()
        }),
        42
    );
}
