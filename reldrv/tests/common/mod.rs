pub mod custom_sysno;
pub mod relrt;

use custom_sysno::TestCustomSysno;
use nix::{
    libc,
    sys::signal::{raise, Signal},
    unistd::{fork, ForkResult},
};
pub use reldrv::RelShellOptions;
use reldrv::{
    parent_work,
    types::{custom_sysno::CustomSysno, exit_reason::ExitReason},
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
    unsafe { libc::syscall(CustomSysno::CheckpointTake as _) };
}

pub fn checkpoint_fini() {
    unsafe { libc::syscall(CustomSysno::CheckpointFini as _) };
}

#[allow(dead_code)]
pub fn checkpoint_sync() {
    unsafe { libc::syscall(CustomSysno::CheckpointSync as _) };
}

pub fn assert_in_protection() {
    unsafe { libc::syscall(CustomSysno::AssertInProtection as _) };
}

pub fn migrate_checker() {
    unsafe { libc::syscall(TestCustomSysno::MigrateChecker as _) };
}

pub fn take_exec_point() {
    unsafe { libc::syscall(TestCustomSysno::TakeExecPoint as _) };
}

#[must_use]
pub fn trace_w_options<E>(
    f: impl FnOnce() -> Result<(), E>,
    options: RelShellOptions,
) -> reldrv::error::Result<ExitReason> {
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
pub fn trace<E>(f: impl FnOnce() -> Result<(), E>) -> reldrv::error::Result<ExitReason> {
    trace_w_options(
        f,
        RelShellOptionsBuilder::test_serial_default()
            .build()
            .unwrap(),
    )
}
