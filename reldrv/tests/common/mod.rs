pub mod relrt;

use nix::{
    libc,
    sys::signal::{raise, Signal},
    unistd::{fork, ForkResult},
};
pub use reldrv::RelShellOptions;
use reldrv::{
    debug_utils::in_protection_asserter::SYSNO_ASSERT_IN_PROTECTION,
    parent_work,
    syscall_handlers::{SYSNO_CHECKPOINT_FINI, SYSNO_CHECKPOINT_SYNC, SYSNO_CHECKPOINT_TAKE},
    types::exit_reason::ExitReason,
    RelShellOptionsBuilder,
};

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
    unsafe { libc::syscall(SYSNO_CHECKPOINT_TAKE as _) };
}

pub fn checkpoint_fini() {
    unsafe { libc::syscall(SYSNO_CHECKPOINT_FINI as _) };
}

#[allow(dead_code)]
pub fn checkpoint_sync() {
    unsafe { libc::syscall(SYSNO_CHECKPOINT_SYNC as _) };
}

pub fn assert_in_protection() {
    unsafe { libc::syscall(SYSNO_ASSERT_IN_PROTECTION as _) };
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
