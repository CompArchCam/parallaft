// Run with `cargo test benches::signal -- --include-ignored --nocapture --test-threads=1`

use nix::{
    libc,
    sys::signal::{raise, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
};

use crate::common::{checkpoint_fini, checkpoint_take};

use super::run_suite;

extern "C" fn handler(_signum: i32, _siginfo: *mut libc::siginfo_t, _ucontext: *mut libc::c_void) {}

fn kernel_sighandler(n_iters: usize) {
    unsafe {
        sigaction(
            Signal::SIGUSR2,
            &SigAction::new(
                SigHandler::SigAction(handler),
                SaFlags::SA_SIGINFO,
                SigSet::empty(),
            ),
        )
        .unwrap();
    }
    checkpoint_take();
    for _ in 0..n_iters {
        raise(Signal::SIGUSR2).unwrap();
    }
    checkpoint_fini();
}

#[ignore = "benchmark use only"]
#[test]
fn run_signal_bench_set() {
    run_suite("signal", 20, || kernel_sighandler(10000));
}
