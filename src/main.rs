mod checkpoint;
mod compel_parasite;

use checkpoint::{CheckingError, Checkpoint};
use compel::syscalls::{syscall_args, Sysno};
use compel::PieLogger;

use nix::sys::signal::Signal::SIGCHLD;

use parasite::call_remote;
use parasite::commands::verify::VerifyRequest;
use parasite::commands::{Request, Response};

use std::cell::RefCell;
use std::collections::HashMap;
use std::ffi::CString;
use std::iter;
use std::rc::Rc;
use std::thread::sleep_ms;

use nix::sched::{sched_setaffinity, CpuSet};
use nix::sys::ptrace;
use nix::sys::signal::{self, raise, Signal};
use nix::sys::wait::{waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};

use clap::Parser;

use log::{error, info};

use crate::compel_parasite::ParasiteCtlSetupHeaderExt;

#[derive(Parser, Debug)]
#[command(version, about)]
struct CliArgs {
    // Main CPU set
    #[arg(short, long, use_value_delimiter = true)]
    main_cpu_set: Vec<usize>,

    // Checker CPU set
    #[arg(short, long, use_value_delimiter = true)]
    checker_cpu_set: Vec<usize>,

    command: String,
    args: Vec<String>,
}

fn set_cpu_affinity(pid: Pid, cpus: &Vec<usize>) {
    if !cpus.is_empty() {
        let mut cpuset = CpuSet::new();
        for cpu in cpus {
            cpuset.set(*cpu).unwrap();
        }
        sched_setaffinity(pid, &cpuset).unwrap();
    }
}

fn parent_work(child_pid: Pid, checker_cpu_set: &Vec<usize>) {
    ptrace::seize(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD | ptrace::Options::PTRACE_O_TRACEFORK,
    )
    .unwrap();
    let status = waitpid(child_pid, None).unwrap();
    assert!(matches!(status, WaitStatus::Stopped(_, _)));
    info!("Child process tracing started");

    let mut pending_request: Option<i32> = None;
    let _pie_logger = PieLogger::new();
    let mut checkers: HashMap<Pid, Rc<RefCell<Checkpoint>>> = HashMap::new();
    let mut checkpoint_prev: Option<Rc<RefCell<Checkpoint>>> = None;

    ptrace::syscall(child_pid, None).unwrap();

    loop {
        let status = waitpid(None, None).unwrap();

        match status {
            WaitStatus::Stopped(pid, sig) => {
                info!("Child {} received signal {}", pid, sig);
                let sig_info = ptrace::getsiginfo(pid).unwrap();
                let si_pid = sig_info._pad[1];
                // info!("siginfo is {:?}", sig_info);
                if sig_info.si_signo == SIGCHLD as _
                    && checkers.contains_key(&Pid::from_raw(si_pid))
                {
                    info!("Child received SIGCHLD from the checker, suppressing it");
                    let mut proc = compel::ParasiteCtl::<Request, Response>::prepare(pid.into())
                        .expect("failed to prepare parasite ctl");
                    let waitpid_result = proc
                        .syscall(Sysno::wait4, syscall_args!(si_pid as _, 0, 0, 0))
                        .unwrap();

                    info!("waitpid status = {:}", waitpid_result);
                    ptrace::syscall(pid, None).unwrap();
                } else {
                    ptrace::syscall(pid, sig).unwrap();
                }
            }
            WaitStatus::Exited(pid, _) => {
                info!("Child {} exited", pid);
                if pid == child_pid {
                    // std::thread::sleep_ms(100000);
                    break;
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                let syscall_info = ptrace::getsyscallinfo(pid).unwrap();
                // debug!("ptrace syscall from {}", pid);
                // debug!("Child syscall info = {:?}", syscall_info);

                let mut do_ptrace_syscall = true;

                match syscall_info.op {
                    ptrace::SyscallInfoOp::Entry { nr: 0xff77, args } => {
                        let arg = args[0];

                        match arg {
                            0 => {
                                info!("Got checkpoint request from {}", pid);
                                assert!(
                                    pid == child_pid,
                                    "unexpected checkpoint request from pid {}, expected {}",
                                    pid,
                                    child_pid
                                );
                                pending_request = Some(0);
                            }
                            1 => {
                                info!("Got verify request from {}", pid);

                                if let Some(checkpoint) = checkers.get_mut(&pid) {
                                    info!("Checker called verify");

                                    if let Some(checkpoint_next) = &checkpoint.borrow().next {
                                        let checkpoint_next = checkpoint_next
                                            .as_ref()
                                            .borrow_mut()
                                            .try_check_from_prev(&_pie_logger)
                                            .expect("failed to check from previous checkpoint");

                                        if !checkpoint_next {
                                            panic!("Check did not pass");
                                        } else {
                                            info!("Check passed");
                                        }
                                        do_ptrace_syscall = false;
                                    } else {
                                        info!("Main process hasn't reached the next checkpoint");
                                    }
                                }
                            }
                            _ => {
                                error!("Unsupported request");
                            }
                        }
                    }
                    ptrace::SyscallInfoOp::Exit {
                        ret_val: _,
                        is_error: _,
                    } => {
                        if pid != child_pid {
                            return;
                        }
                        match pending_request {
                            Some(0) => {
                                // checkpoint
                                let mut proc =
                                    compel::ParasiteCtl::<Request, Response>::prepare(pid.into())
                                        .expect("failed to prepare parasite ctl");

                                // spawn checker process
                                let result = proc
                                    .syscall(
                                        Sysno::clone,
                                        syscall_args!(libc::SIGCHLD as _, 0, 0, 0, 0),
                                    )
                                    .expect("failed to fork");

                                let checker_pid = Pid::from_raw(result as _);
                                info!("Checker pid is {}", checker_pid);
                                set_cpu_affinity(checker_pid, checker_cpu_set);

                                // spawn reference process

                                let ref_pid = match checkpoint_prev {
                                    Some(_) => {
                                        let result = proc
                                            .syscall(
                                                Sysno::clone,
                                                syscall_args!(libc::SIGCHLD as _, 0, 0, 0, 0),
                                            )
                                            .expect("failed to fork");
                                        Some(Pid::from_raw(result as _))
                                    }
                                    None => None,
                                };

                                info!("Reference pid is {:?}", ref_pid);

                                // create a checkpoint object
                                let checkpoint = Checkpoint::new_rced(
                                    checker_pid,
                                    ref_pid,
                                    checkpoint_prev.take(),
                                );

                                // do the check if it hasn't been checked
                                match checkpoint
                                    .as_ref()
                                    .borrow_mut()
                                    .try_check_from_prev(&_pie_logger)
                                {
                                    Ok(true) => info!("Checking passed"),
                                    Ok(false) => panic!("Checking did not pass"),
                                    Err(CheckingError::AlreadyChecked) => info!("Already checked"),
                                    Err(CheckingError::NoPreviousCheckpoint) => (),
                                }

                                // update the global mapping
                                checkers.insert(checker_pid, checkpoint.clone());
                                checkpoint_prev = Some(checkpoint);
                            }
                            _ => (),
                        }
                        pending_request = None;
                    }
                    _ => (),
                }

                if do_ptrace_syscall {
                    // info!("== resuming process {:?}", pid);
                    ptrace::syscall(pid, None).unwrap();
                }
            }
            WaitStatus::PtraceEvent(_pid, _, event) => {
                info!("Syscall event = {:}", event);
            }
            _ => (),
        }
    }

    sleep_ms(10000);
}

fn main() {
    env_logger::init();
    compel::log_init(log::Level::Error);

    let cli = CliArgs::parse();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent_work(child, &cli.checker_cpu_set),
        Ok(ForkResult::Child) => {
            let argv: Vec<CString> = iter::once(cli.command)
                .chain(cli.args.into_iter())
                .map(|str| CString::new(str).unwrap())
                .collect();

            set_cpu_affinity(Pid::this(), &cli.main_cpu_set);

            // ptrace::traceme().unwrap();
            raise(Signal::SIGSTOP).unwrap();
            execvp(&argv[0], &argv).unwrap();
        }
        Err(err) => panic!("Fork failed: {}", err),
    }
}
