mod checkpoint;
mod compel_parasite;
mod dirty_page_tracer;
mod page_diff;
mod process;
mod utils;

use std::ffi::CString;
use std::iter;

use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::{wait, waitpid, WaitStatus};
use nix::unistd::{execvp, fork, ForkResult, Pid};

use clap::Parser;

use log::info;

use crate::checkpoint::CheckCoordinator;
use crate::process::Process;

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

fn parent_work(child_pid: Pid, checker_cpu_set: &Vec<usize>, main_cpu_set: &Vec<usize>) {
    ptrace::seize(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK,
    )
    .unwrap();
    let status = waitpid(child_pid, None).unwrap();
    assert!(matches!(status, WaitStatus::Stopped(_, _)));
    info!("Child process tracing started");

    let mut check_coord = CheckCoordinator::new(Process::new(child_pid, None), checker_cpu_set);
    check_coord.main.set_cpu_affinity(main_cpu_set);
    check_coord.main.resume();

    let mut main_finished = false;

    loop {
        let status = wait().unwrap();

        match status {
            WaitStatus::Stopped(pid, sig) => {
                let sig_info = ptrace::getsiginfo(pid).unwrap();
                #[allow(deprecated)]
                let from_pid = Pid::from_raw(sig_info._pad[1] as _);
                info!("Child {} received signal {} from {}", pid, sig, from_pid);

                #[cfg(not(feature = "dont_handle_sigchld"))]
                let handled = check_coord.handle_sigchld(pid, from_pid);
                #[cfg(feature = "dont_handle_sigchld")]
                let handled = true;
                ptrace::syscall(pid, if handled { None } else { Some(sig) }).unwrap();
            }
            WaitStatus::Exited(pid, _) => {
                info!("Child {} exited", pid);
                break;
            }
            WaitStatus::PtraceSyscall(pid) => {
                let syscall_info = ptrace::getsyscallinfo(pid);

                let syscall_info = match syscall_info {
                    Ok(syscall_info) => syscall_info,
                    Err(Errno::ESRCH) => continue, // TODO: why?
                    err => panic!("failed to get syscall info: {:?}", err),
                };

                // TODO: fix random zombie process

                match syscall_info.op {
                    ptrace::SyscallInfoOp::Entry { nr: 0xff77, .. } => {
                        info!("Checkpoint requested by {}", pid);
                        check_coord.handle_checkpoint(pid, false);
                    }
                    ptrace::SyscallInfoOp::Entry { nr: 0xff78, .. } => {
                        info!("Checkpoint finish requested by {}", pid);
                        check_coord.handle_checkpoint(pid, true);
                    }
                    ptrace::SyscallInfoOp::Entry { nr, .. }
                        if [
                            libc::SYS_rseq,
                            // libc::SYS_get_robust_list,
                            // libc::SYS_set_robust_list,
                            // libc::SYS_set_tid_address,
                            // libc::SYS_arch_prctl,
                        ]
                        .contains(&nr) =>
                    {
                        info!("Rewriting unsupported syscall {}", nr);
                        let mut regs = ptrace::getregs(pid).expect("failed to get registers");
                        regs.orig_rax = 0xff77;
                        regs.rax = 0xff77; // invalid syscall
                        ptrace::setregs(pid, regs).expect("failed to set registers");
                        ptrace::syscall(pid, None).unwrap();
                    }
                    ptrace::SyscallInfoOp::Entry { nr, .. }
                        if [libc::SYS_exit, libc::SYS_exit_group].contains(&nr as _) =>
                    {
                        info!("Child called exit");
                        assert!(pid == child_pid);
                        main_finished = true;
                        if check_coord.is_all_finished() {
                            ptrace::syscall(pid, None).unwrap();
                        }
                    }
                    _ => {
                        ptrace::syscall(pid, None).unwrap();
                    }
                }
            }
            WaitStatus::PtraceEvent(_pid, _sig, event) => {
                info!("Ptrace event = {:}", event);
            }
            WaitStatus::Signaled(pid, sig, _) => {
                info!("PID {} signaled by {}", pid, sig);
                if main_finished && check_coord.is_all_finished() {
                    break;
                }
            }
            _ => (),
        }
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    compel::log_init(log::Level::Error);

    let cli = CliArgs::parse();

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => {
            parent_work(child, &cli.checker_cpu_set, &cli.main_cpu_set)
        }
        Ok(ForkResult::Child) => {
            let argv: Vec<CString> = iter::once(cli.command)
                .chain(cli.args.into_iter())
                .map(|str| CString::new(str).unwrap())
                .collect();

            raise(Signal::SIGSTOP).unwrap();
            execvp(&argv[0], &argv).unwrap();
        }
        Err(err) => panic!("Fork failed: {}", err),
    }
}
