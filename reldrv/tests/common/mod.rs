pub mod relrt;

use nix::{
    libc,
    sys::signal::{raise, Signal},
    unistd::{fork, ForkResult},
};
pub use reldrv::RelShellOptions;
use reldrv::{check_coord::ExitReason, parent_work, RelShellOptionsBuilder};

use std::sync::Once;

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        pretty_env_logger::formatted_builder()
            .parse_default_env()
            .is_test(true)
            .init();
    });
}

pub fn checkpoint_take() {
    unsafe { libc::syscall(0xff77) };
}

pub fn checkpoint_fini() {
    unsafe { libc::syscall(0xff78) };
}

#[allow(dead_code)]
pub fn checkpoint_sync() {
    unsafe { libc::syscall(0xff79) };
}

#[must_use]
pub fn trace_w_options<E>(
    f: impl FnOnce() -> Result<(), E>,
    options: RelShellOptions,
) -> ExitReason {
    setup();

    // TODO: ensure there are no leftover processes

    match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => parent_work(child, options),
        ForkResult::Child => {
            raise(Signal::SIGSTOP).unwrap();
            let code = match f() {
                Err(_) => 1,
                Ok(_) => 0,
            };
            std::process::exit(code);
        }
    }
}

#[must_use]
pub fn trace<E>(f: impl FnOnce() -> Result<(), E>) -> ExitReason {
    trace_w_options(
        f,
        RelShellOptionsBuilder::test_serial_default()
            .build()
            .unwrap(),
    )
}
