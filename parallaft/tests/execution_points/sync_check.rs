use std::convert::Infallible;

use parallaft::RelShellOptionsBuilder;

use crate::common::{check_exec_point_sync, checkpoint_fini, checkpoint_take, trace_w_options};

#[test]
fn test_exec_point_sync_check_normal() {
    trace_w_options(
        || {
            checkpoint_take();

            for _ in 0..100 {
                check_exec_point_sync();
            }

            checkpoint_fini();
            Ok::<_, Infallible>(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .test_with_exec_point_replay()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect();
}

#[test]
fn test_exec_point_sync_check_outside_protection_zone() {
    trace_w_options(
        || {
            check_exec_point_sync();
            Ok::<_, Infallible>(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .test_with_exec_point_replay()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect();
}
