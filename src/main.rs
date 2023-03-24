mod checkpoint;
mod compel_parasite;
mod dirty_page_tracer;
mod page_diff;
mod process;
mod utils;

use std::os::unix::process::CommandExt;
use std::process::Command;
use std::time::{Duration, Instant};

use bitflags::bitflags;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::{wait, waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

use clap::Parser;

use log::info;

use crate::checkpoint::{CheckCoordinator, CheckCoordinatorFlags};
use crate::process::Process;

#[derive(Parser, Debug)]
#[command(version, about)]
struct CliArgs {
    /// Main CPU set
    #[arg(short, long, use_value_delimiter = true)]
    main_cpu_set: Vec<usize>,

    /// Checker CPU set
    #[arg(short, long, use_value_delimiter = true)]
    checker_cpu_set: Vec<usize>,

    /// Poll non-blocking waitpid instead of using blocking waitpid.
    #[arg(long)]
    poll_waitpid: bool,

    /// Don't compare dirty memory between the checker and the reference.
    #[arg(long)]
    no_mem_check: bool,

    /// Don't run the checker process. Just fork, and kill it until the next checkpoint.
    #[arg(long)]
    dont_run_checker: bool,

    /// Don't clear soft-dirty bits in each iteration. Depends on `--no-mem-check`.
    #[arg(long)]
    dont_clear_soft_dirty: bool,

    /// Check dirty memory synchronously.
    #[arg(long)]
    sync_mem_check: bool,

    /// Use libcompel for syscall injection, instead of using ptrace directly.
    #[arg(long)]
    use_libcompel: bool,

    /// Dump statistics.
    #[arg(long)]
    dump_stats: bool,

    /// Checkpoint frequency to pass to the main process.
    #[arg(long, default_value_t = 1)]
    checkpoint_freq: u32,

    command: String,
    args: Vec<String>,
}

bitflags! {
    struct RunnerFlags: u32 {
        const POLL_WAITPID = 0b00000001;
        const DUMP_STATS = 0b00000010;
    }
}

fn parent_work(
    child_pid: Pid,
    checker_cpu_set: &Vec<usize>,
    main_cpu_set: &Vec<usize>,
    flags: RunnerFlags,
    check_coord_flags: CheckCoordinatorFlags,
) {
    info!("Starting");
    let status = waitpid(child_pid, Some(WaitPidFlag::WSTOPPED)).unwrap();
    assert_eq!(status, WaitStatus::Stopped(child_pid, Signal::SIGSTOP));
    ptrace::seize(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK,
    )
    .unwrap();

    info!("Child process tracing started");

    let check_coord = CheckCoordinator::new(
        Process::new(child_pid, None),
        checker_cpu_set,
        check_coord_flags,
    );

    check_coord.main.set_cpu_affinity(main_cpu_set);
    check_coord.main.resume();

    let mut main_finished = false;
    let mut main_exec_time = Duration::ZERO;

    let exec_start_time = Instant::now();

    loop {
        let status = if flags.contains(RunnerFlags::POLL_WAITPID) {
            waitpid(None, Some(WaitPidFlag::WNOHANG)).unwrap()
        } else {
            wait().unwrap()
        };

        match status {
            WaitStatus::Stopped(pid, sig) => ptrace::syscall(pid, sig).unwrap(),
            WaitStatus::Exited(pid, _) => {
                info!("Child {} exited", pid);
                if pid == check_coord.main.pid {
                    main_finished = true;
                    main_exec_time = exec_start_time.elapsed();

                    if check_coord.is_all_finished() {
                        break;
                    }
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                let syscall_info = ptrace::getsyscallinfo(pid);

                let syscall_info = match syscall_info {
                    Ok(syscall_info) => syscall_info,
                    Err(Errno::ESRCH) => continue, // TODO: why?
                    err => panic!("failed to get syscall info: {:?}", err),
                };

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
                    // ptrace::SyscallInfoOp::Entry { nr, .. }
                    //     if [libc::SYS_exit, libc::SYS_exit_group].contains(&nr as _) =>
                    // {
                    //     info!("Child called exit");
                    //     assert!(pid == child_pid);
                    //     main_finished.store(true, Ordering::SeqCst);
                    //     if check_coord.is_all_finished() {
                    //         ptrace::syscall(pid, None).unwrap();
                    //     }
                    // }
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

    let all_exec_time = exec_start_time.elapsed();

    if flags.contains(RunnerFlags::DUMP_STATS) {
        let nr_checkpoints = check_coord.epoch();
        println!("main_exec_time={}", main_exec_time.as_secs_f64());
        println!("all_exec_time={}", all_exec_time.as_secs_f64());
        println!("nr_checkpoints={}", nr_checkpoints);
        println!(
            "avg_checkpoint_freq={}",
            (nr_checkpoints as f64) / main_exec_time.as_secs_f64()
        );
        println!("avg_nr_dirty_pages={}", check_coord.avg_nr_dirty_pages());
    }
}

#[tokio::main]
async fn main() {
    env_logger::init();
    compel::log_init(log::Level::Error);

    let cli = CliArgs::parse();

    let mut runner_flags = RunnerFlags::empty();
    runner_flags.set(RunnerFlags::POLL_WAITPID, cli.poll_waitpid);
    runner_flags.set(RunnerFlags::DUMP_STATS, cli.dump_stats);

    let mut check_coord_flags = CheckCoordinatorFlags::empty();
    check_coord_flags.set(CheckCoordinatorFlags::SYNC_MEM_CHECK, cli.sync_mem_check);
    check_coord_flags.set(CheckCoordinatorFlags::NO_MEM_CHECK, cli.no_mem_check);
    check_coord_flags.set(
        CheckCoordinatorFlags::DONT_RUN_CHECKER,
        cli.dont_run_checker,
    );
    check_coord_flags.set(
        CheckCoordinatorFlags::DONT_CLEAR_SOFT_DIRTY,
        cli.dont_clear_soft_dirty,
    );
    check_coord_flags.set(CheckCoordinatorFlags::USE_LIBCOMPEL, cli.use_libcompel);

    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent_work(
            child,
            &cli.checker_cpu_set,
            &cli.main_cpu_set,
            runner_flags,
            check_coord_flags,
        ),
        Ok(ForkResult::Child) => {
            let err = unsafe {
                Command::new(cli.command)
                    .args(cli.args)
                    .env("CHECKER_CHECKPOINT_FREQ", cli.checkpoint_freq.to_string())
                    .pre_exec(|| {
                        raise(Signal::SIGSTOP).unwrap();
                        Ok(())
                    })
                    .exec()
            };
            panic!("failed to spawn subcommand: {:?}", err);
        }
        Err(err) => panic!("Fork failed: {}", err),
    }
}
