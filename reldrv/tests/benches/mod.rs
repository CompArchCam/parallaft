use std::{convert::Infallible, time::Duration};

use nix::{
    sys::{
        ptrace,
        signal::{raise, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{fork, ForkResult},
};
use reldrv::{
    check_coord::CheckCoordinatorOptionsBuilder,
    process::{
        state::{Stopped, WithProcess},
        Process,
    },
    RelShellOptionsBuilder,
};

use crate::common::trace_w_options;

mod checkpointing;
mod signal;
mod syscall;

fn measure_time<T>(f: impl FnOnce() -> T) -> (T, Duration) {
    let start = std::time::Instant::now();
    let result = f();
    let elapsed = start.elapsed();
    (result, elapsed)
}

fn ptraced(f: impl FnOnce() -> i32) -> Process<Stopped> {
    match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => {
            let wait_status = waitpid(child, Some(WaitPidFlag::WSTOPPED)).unwrap();
            assert_eq!(wait_status, WaitStatus::Stopped(child, Signal::SIGSTOP));
            ptrace::seize(
                child,
                ptrace::Options::PTRACE_O_TRACESYSGOOD
                    | ptrace::Options::PTRACE_O_TRACECLONE
                    | ptrace::Options::PTRACE_O_TRACEFORK
                    | ptrace::Options::PTRACE_O_EXITKILL,
            )
            .unwrap();
            Process::new(child, Stopped)
        }
        ForkResult::Child => {
            raise(Signal::SIGSTOP).unwrap();
            let code = f();
            std::process::exit(code)
        }
    }
}

fn run_under_ptrace(f: impl FnOnce()) -> reldrv::error::Result<()> {
    let mut process = ptraced(|| {
        f();
        0
    });

    let mut process_running = process.resume()?;

    loop {
        let status;
        WithProcess(process, status) = process_running.waitpid()?.unwrap_stopped();

        match status {
            WaitStatus::Exited(_, _) => break,
            WaitStatus::Signaled(_, _, _) => break,
            WaitStatus::Stopped(_, sig) => {
                process_running = process.resume_with_signal(sig)?;
            }
            _ => {
                process_running = process.resume()?;
            }
        }
    }

    Ok(())
}

fn run_under_parallaft(f: impl FnOnce()) {
    trace_w_options(
        || {
            f();
            Ok::<_, Infallible>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .check_coord_flags(
                CheckCoordinatorOptionsBuilder::default()
                    .no_checker_exec(true)
                    .build()
                    .unwrap(),
            )
            .test_with_exec_point_replay()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect();
}

fn run_suite(name: &'static str, f: impl Fn()) {
    let (_, time_base) = measure_time(&f);
    println!("{} base: {}", name, time_base.as_secs_f64());

    let (_, time_ptrace) = measure_time(|| run_under_ptrace(&f));
    println!("{} ptrace: {}", name, time_ptrace.as_secs_f64());

    let (_, time_parallalft) = measure_time(|| run_under_parallaft(&f));
    println!("{} parallaft: {}", name, time_parallalft.as_secs_f64());

    println!(
        "{} ptrace slowdown: {}",
        name,
        time_ptrace.as_secs_f64() / time_base.as_secs_f64()
    );

    println!(
        "{} parallaft slowdown: {}",
        name,
        time_parallalft.as_secs_f64() / time_base.as_secs_f64()
    );
}
