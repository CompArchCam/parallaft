use crate::common::{checkpoint_fini, checkpoint_take, setup, trace_with_options, RelShellOptions};
use nix::libc;
use serial_test::serial;

#[test]
#[serial]
fn limit_1() {
    setup();

    assert_eq!(
        trace_with_options(
            || {
                for _ in 0..20 {
                    checkpoint_take();
                }
                checkpoint_fini();
                0
            },
            RelShellOptions::new().with_max_nr_live_segments(1)
        ),
        0
    );
}

#[test]
#[serial]
fn limit_8_getpid_loop() {
    setup();

    assert_eq!(
        trace_with_options(
            || {
                for _ in 0..2000 {
                    checkpoint_take();
                    unsafe { libc::getpid() };
                }
                checkpoint_fini();
                0
            },
            RelShellOptions::new().with_max_nr_live_segments(8)
        ),
        0
    );
}
