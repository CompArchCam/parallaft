use std::{convert::Infallible, time::Duration};

use nix::{
    sys::{
        ptrace,
        signal::{raise, Signal},
        wait::{waitpid, WaitPidFlag, WaitStatus},
    },
    unistd::{fork, ForkResult},
};
use parallaft::{
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

fn run_in_new_process(f: impl FnOnce()) -> i32 {
    match unsafe { fork().unwrap() } {
        ForkResult::Parent { child } => {
            let wait_status = waitpid(child, None).unwrap();
            assert_eq!(wait_status, WaitStatus::Exited(child, 0));
            0
        }
        ForkResult::Child => {
            f();
            std::process::exit(0)
        }
    }
}

fn run_under_ptrace(f: impl FnOnce()) -> parallaft::error::Result<()> {
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

fn run_suite(name: &'static str, repeat: usize, f: impl Fn()) {
    let mut time_base_all = Vec::new();
    let mut time_ptrace_all = Vec::new();
    let mut time_parallalft_all = Vec::new();

    for i in 0..repeat {
        println!("===== {i}th run =====");

        let (_, time_base) = measure_time(|| run_in_new_process(&f));
        println!("{} base: {}", name, time_base.as_secs_f64());

        let (_, time_ptrace) = measure_time(|| run_under_ptrace(&f));
        println!("{} ptrace: {}", name, time_ptrace.as_secs_f64());

        let (_, time_parallalft) = measure_time(|| run_under_parallaft(&f));
        println!("{} parallaft: {}", name, time_parallalft.as_secs_f64());

        time_base_all.push(time_base);
        time_ptrace_all.push(time_ptrace);
        time_parallalft_all.push(time_parallalft);

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

    let time_base_avg = time_base_all.iter().map(|t| t.as_secs_f64()).sum::<f64>() / repeat as f64;
    let time_ptrace_avg =
        time_ptrace_all.iter().map(|t| t.as_secs_f64()).sum::<f64>() / repeat as f64;

    let time_parallalft_avg = time_parallalft_all
        .iter()
        .map(|t| t.as_secs_f64())
        .sum::<f64>()
        / repeat as f64;

    println!("===== summary =====");
    println!("{} base: {}", name, time_base_avg);
    println!("{} ptrace: {}", name, time_ptrace_avg);
    println!("{} parallaft: {}", name, time_parallalft_avg);

    println!(
        "{} ptrace slowdown: {}",
        name,
        time_ptrace_avg / time_base_avg
    );

    println!(
        "{} parallaft slowdown: {}",
        name,
        time_parallalft_avg / time_base_avg
    );
}
