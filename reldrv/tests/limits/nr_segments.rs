use crate::common::{checkpoint_fini, checkpoint_take, trace, trace_w_options};
use nix::libc;
use reldrv::RelShellOptionsBuilder;

#[test]
fn limit_1() {
    trace(|| {
        for _ in 0..20 {
            checkpoint_take();
        }
        checkpoint_fini();

        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn limit_8_getpid_loop() {
    trace_w_options(
        || {
            for _ in 0..2000 {
                checkpoint_take();
                unsafe { libc::getpid() };
            }
            checkpoint_fini();

            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .build()
            .unwrap(),
    )
    .expect()
}
