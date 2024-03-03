use std::arch::x86_64::__cpuid_count;

use reldrv::RelShellOptionsBuilder;

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

#[test]

fn cpuid() {
    trace_w_options(
        || {
            checkpoint_take();
            unsafe {
                __cpuid_count(0, 0);
                __cpuid_count(1, 0);
                __cpuid_count(2, 0);
                __cpuid_count(3, 0);
                __cpuid_count(6, 0);
                __cpuid_count(7, 0);
                __cpuid_count(7, 1);
                __cpuid_count(7, 2);
            }
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .no_cpuid_trap(false) // enable CPUID trapping
            .build()
            .unwrap(),
    )
    .expect()
}
