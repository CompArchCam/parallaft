use std::arch::x86_64::__cpuid_count;

use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};

use serial_test::serial;

#[test]
#[serial]
fn test_cpuid() {
    setup();
    assert_eq!(
        trace(|| {
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
            0
        }),
        0
    )
}