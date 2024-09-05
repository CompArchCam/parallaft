use std::{
    arch::x86_64::{__rdtscp, _rdtsc},
    mem::MaybeUninit,
};

use reldrv::{types::exit_reason::ExitReason, RelShellOptionsBuilder};

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

#[must_use]
fn trace_w_rdtsc_trapping<E>(f: impl FnOnce() -> Result<(), E>) -> ExitReason {
    trace_w_options(
        f,
        RelShellOptionsBuilder::test_serial_default()
            .no_rdtsc_trap(false)
            .build()
            .unwrap(),
    )
}

#[test]
fn rdtsc() {
    trace_w_rdtsc_trapping(|| {
        checkpoint_take();
        unsafe { _rdtsc() };
        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn rdtsc_loop() {
    trace_w_rdtsc_trapping(|| {
        let mut prev_tsc: u64 = 0;
        checkpoint_take();

        for _ in 0..1000 {
            let tsc = unsafe { _rdtsc() };
            assert!(tsc > prev_tsc);
            prev_tsc = tsc;
        }

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn rdtsc_outside_protected_region() {
    trace_w_rdtsc_trapping(|| {
        unsafe { _rdtsc() };
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn rdtscp() {
    trace_w_rdtsc_trapping(|| {
        checkpoint_take();
        let mut aux = MaybeUninit::uninit();
        unsafe { __rdtscp(aux.as_mut_ptr()) };
        unsafe { aux.assume_init() };
        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn rdtscp_loop() {
    trace_w_rdtsc_trapping(|| {
        let mut prev_tsc: u64 = 0;
        checkpoint_take();

        for _ in 0..1000 {
            let mut aux = MaybeUninit::uninit();
            let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
            assert!(tsc > prev_tsc);
            prev_tsc = tsc;
        }

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}

#[test]
fn rdtscp_outside_protected_region() {
    trace_w_rdtsc_trapping(|| {
        let mut aux = MaybeUninit::uninit();
        unsafe { __rdtscp(aux.as_mut_ptr()) };
        Ok::<_, ()>(())
    })
    .unwrap()
    .expect()
}
