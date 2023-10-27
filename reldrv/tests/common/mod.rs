pub mod relrt;

use nix::{
    libc,
    sys::signal::{raise, Signal},
    unistd::{fork, ForkResult},
};
use reldrv::parent_work;
pub use reldrv::RelShellOptions;
use std::sync::Once;

static INIT: Once = Once::new();

pub fn setup() {
    INIT.call_once(|| {
        env_logger::builder().is_test(true).init();

        // let orig_hook = panic::take_hook();
        // panic::set_hook(Box::new(move |panic_info| {
        //     orig_hook(panic_info);
        //     std::process::exit(1);
        // }));
    });
}

pub fn trace_with_options(f: impl FnOnce() -> i32, options: RelShellOptions) -> i32 {
    match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => parent_work(child, options),
        ForkResult::Child => {
            raise(Signal::SIGSTOP).unwrap();
            let code = f();
            std::process::exit(code);
        }
    }
}

pub fn trace(f: impl FnOnce() -> i32) -> i32 {
    trace_with_options(f, Default::default())
}

pub fn checkpoint_take() {
    unsafe { libc::syscall(0xff77) };
}

pub fn checkpoint_fini() {
    unsafe { libc::syscall(0xff78) };
}

pub fn checkpoint_sync() {
    unsafe { libc::syscall(0xff79) };
}

pub fn setup_trace_and_unwrap_with_options<T, E>(
    f: impl FnOnce() -> Result<T, E>,
    options: RelShellOptions,
) {
    setup();

    assert_eq!(
        trace_with_options(
            || {
                match f() {
                    Err(_) => 1,
                    Ok(_) => 0,
                }
            },
            options
        ),
        0
    );
}
