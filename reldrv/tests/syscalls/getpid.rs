use crate::common::{checkpoint_fini, checkpoint_take, trace};
use nix::libc;

#[test]
fn getpid_once() {
    trace(|| {
        checkpoint_take();
        unsafe { libc::getpid() };
        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn getpid_loop() {
    trace(|| {
        let orig_pid = unsafe { libc::getpid() };

        checkpoint_take();

        for _ in 0..20 {
            let pid = unsafe { libc::getpid() };
            assert_eq!(pid, orig_pid);
        }

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn checkpoint_getpid_loop() {
    trace(|| {
        let orig_pid = unsafe { libc::getpid() };

        for _ in 0..20 {
            checkpoint_take();
            let pid = unsafe { libc::getpid() };
            assert_eq!(pid, orig_pid);
        }

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}
