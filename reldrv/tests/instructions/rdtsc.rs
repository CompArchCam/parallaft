use std::{
    arch::x86_64::{__rdtscp, _rdtsc},
    mem::MaybeUninit,
};

use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};

use serial_test::serial;

#[test]
#[serial]
fn rdtsc() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            let _tsc = unsafe { _rdtsc() };
            checkpoint_fini();
            0
        }),
        0
    )
}

#[test]
#[serial]
fn rdtsc_loop() {
    setup();
    assert_eq!(
        trace(|| {
            let mut prev_tsc: u64 = 0;
            checkpoint_take();

            for _ in 0..1000 {
                let tsc = unsafe { _rdtsc() };
                assert!(tsc > prev_tsc);
                prev_tsc = tsc;
            }

            checkpoint_fini();
            0
        }),
        0
    )
}

#[test]
#[serial]
fn rdtsc_outside_protected_region() {
    setup();
    assert_eq!(
        trace(|| {
            unsafe { _rdtsc() };
            0
        }),
        0
    )
}

#[test]
#[serial]
fn rdtscp() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            let mut aux = MaybeUninit::uninit();
            let _tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
            let _aux = unsafe { aux.assume_init() };
            checkpoint_fini();
            0
        }),
        0
    )
}

#[test]
#[serial]
fn rdtscp_loop() {
    setup();
    assert_eq!(
        trace(|| {
            let mut prev_tsc: u64 = 0;
            checkpoint_take();

            for _ in 0..1000 {
                let mut aux = MaybeUninit::uninit();
                let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
                assert!(tsc > prev_tsc);
                prev_tsc = tsc;
            }

            checkpoint_fini();
            0
        }),
        0
    )
}

#[test]
#[serial]
fn rdtscp_outside_protected_region() {
    setup();
    assert_eq!(
        trace(|| {
            let mut aux = MaybeUninit::uninit();
            unsafe { __rdtscp(aux.as_mut_ptr()) };
            0
        }),
        0
    )
}
