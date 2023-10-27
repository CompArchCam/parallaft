use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};
use nix::libc;
use serial_test::serial;

#[test]
#[serial]
fn brk() {
    setup();
    assert_eq!(
        trace(|| {
            const LEN: usize = 16384;

            checkpoint_take();

            let ptr = unsafe { libc::sbrk(LEN as _) };
            assert_ne!(ptr, -1_isize as *mut libc::c_void);

            let s = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, LEN) };

            // ensure we can read and write without causing a segfault
            s.fill(42);
            assert!(s.iter().all(|&x| x == 42));

            checkpoint_fini();
            0
        }),
        0
    );
}
