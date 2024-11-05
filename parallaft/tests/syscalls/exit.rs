use crate::common::{checkpoint_take, trace};
use nix::libc;

#[test]
fn exit() {
    trace::<()>(|| {
        checkpoint_take();
        unsafe { libc::syscall(libc::SYS_exit, 42) };
        unreachable!()
    })
    .unwrap()
    .expect_exit_code(42)
}

#[test]
fn exit_group() {
    trace::<()>(|| {
        checkpoint_take();
        unsafe { libc::syscall(libc::SYS_exit_group, 42) };
        unreachable!()
    })
    .unwrap()
    .expect_exit_code(42)
}
