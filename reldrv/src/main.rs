mod checkpoint;
mod client_control;
#[cfg(feature = "compel")]
mod compel_parasite;

mod dirty_page_tracer;
mod page_diff;
mod process;
mod remote_memory;
mod saved_syscall;
mod segments;

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::{Command, ExitCode};
use std::sync::mpsc;
use std::time::{Duration, Instant};

use bitflags::bitflags;
use nix::errno::Errno;
use nix::sys::ptrace;
use nix::sys::signal::{raise, sigaction, SaFlags, SigAction, SigHandler, Signal};
use nix::sys::signalfd::SigSet;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, gettid, ForkResult, Pid};

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

    /// Don't fork the main process. Implies `--dont-run-checker`, `--no-mem-check` and `--dont-clear-soft-dirty`.
    #[arg(long)]
    dont_fork: bool,

    /// Check dirty memory synchronously.
    #[arg(long)]
    sync_mem_check: bool,

    /// Ignore check errors.
    #[arg(long)]
    ignore_check_errors: bool,

    #[cfg(feature = "compel")]
    /// Use libcompel for syscall injection, instead of using ptrace directly.
    #[arg(long)]
    use_libcompel: bool,

    /// Dump statistics.
    #[arg(long)]
    dump_stats: bool,

    /// File to dump stats to.
    #[arg(long)]
    stats_output: Option<PathBuf>,

    /// File to write logs to.
    #[arg(long)]
    log_output: Option<PathBuf>,

    /// Checkpoint frequency to pass to the main process.
    #[arg(long, default_value_t = 1)]
    checkpoint_freq: u32,

    /// Maximum number of live segments (0 = unlimited).
    #[arg(long, default_value_t = 8)]
    max_nr_live_segments: usize,

    command: String,
    args: Vec<String>,
}

bitflags! {
    struct RunnerFlags: u32 {
        const POLL_WAITPID = 0b00000001;
        const DUMP_STATS = 0b00000010;
    }
}

static mut WATIPID_FLAGS: WaitPidFlag = WaitPidFlag::empty();

extern "C" fn sigusr1_handler(
    _sig: nix::libc::c_int,
    _info: *mut nix::libc::siginfo_t,
    _uctx: *mut nix::libc::c_void,
) {
    unsafe { WATIPID_FLAGS = WaitPidFlag::WNOHANG };
}

fn parent_work(
    child_pid: Pid,
    checker_cpu_set: &Vec<usize>,
    main_cpu_set: &Vec<usize>,
    flags: RunnerFlags,
    check_coord_flags: CheckCoordinatorFlags,
    stats_output: Option<PathBuf>,
    max_nr_live_segments: usize,
) -> i32 {
    info!("Starting");

    let mut sigset = SigSet::empty();
    sigset.add(Signal::SIGUSR1);
    sigset.thread_block().unwrap();

    let sa = SigAction::new(
        SigHandler::SigAction(sigusr1_handler),
        SaFlags::empty(),
        SigSet::empty(),
    );
    unsafe { sigaction(Signal::SIGUSR1, &sa).unwrap() };

    let status = waitpid(child_pid, Some(WaitPidFlag::WSTOPPED)).unwrap();
    assert_eq!(status, WaitStatus::Stopped(child_pid, Signal::SIGSTOP));
    ptrace::seize(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_EXITKILL,
    )
    .unwrap();

    info!("Child process tracing started");

    let (tracer_op_tx, tracer_op_rx) = mpsc::sync_channel(1024);

    let check_coord = CheckCoordinator::new(
        Process::new(child_pid, gettid(), Some(tracer_op_tx)),
        checker_cpu_set,
        check_coord_flags,
        max_nr_live_segments,
    );

    check_coord.main.set_cpu_affinity(main_cpu_set);
    check_coord.main.resume();

    let mut main_finished = false;
    let mut main_exec_time = Duration::ZERO;

    let exec_start_time = Instant::now();
    let mut syscall_cnt = 0;

    let mut last_syscall_entry_handled_by_check_coord: HashMap<Pid, bool> = HashMap::new();

    let mut exit_status = None;

    loop {
        loop {
            match tracer_op_rx.try_recv() {
                Ok(op) => match op {
                    process::TracerOp::PtraceSyscall(pid) => {
                        ptrace::syscall(pid, None).unwrap();
                    }
                },
                Err(mpsc::TryRecvError::Empty) => break,
                Err(e) => panic!("failed to receive tracer op: {:?}", e),
            }
        }

        unsafe { WATIPID_FLAGS = WaitPidFlag::empty() };
        sigset.thread_unblock().unwrap();

        let status = if flags.contains(RunnerFlags::POLL_WAITPID) {
            waitpid(None, Some(WaitPidFlag::WNOHANG))
        } else {
            waitpid(None, Some(unsafe { WATIPID_FLAGS }))
        };

        sigset.thread_block().unwrap();

        let status = if let Err(Errno::EINTR) = status {
            continue;
        } else {
            status.unwrap()
        };

        match status {
            WaitStatus::Stopped(pid, sig) => ptrace::syscall(pid, sig).unwrap(),
            WaitStatus::Exited(pid, status) => {
                info!("Child {} exited", pid);
                if pid == check_coord.main.pid {
                    main_finished = true;
                    main_exec_time = exec_start_time.elapsed();
                    exit_status = Some(status);

                    if check_coord.is_all_finished() {
                        break;
                    }
                }
            }
            WaitStatus::PtraceSyscall(pid) => {
                let syscall_info = match ptrace::getsyscallinfo(pid) {
                    Ok(syscall_info) => syscall_info,
                    Err(Errno::ESRCH) => continue, // TODO: why?
                    err => panic!("failed to get syscall info: {:?}", err),
                };

                match syscall_info.op {
                    ptrace::SyscallInfoOp::Entry {
                        nr: raw_nr,
                        args: raw_args,
                    } => {
                        if let Some(sysno) = reverie_syscalls::Sysno::new(raw_nr as _) {
                            let args = reverie_syscalls::SyscallArgs {
                                arg0: raw_args[0] as _,
                                arg1: raw_args[1] as _,
                                arg2: raw_args[2] as _,
                                arg3: raw_args[3] as _,
                                arg4: raw_args[4] as _,
                                arg5: raw_args[5] as _,
                            };

                            check_coord.handle_syscall_entry(pid, sysno, args);
                            last_syscall_entry_handled_by_check_coord.insert(pid, true);
                        } else {
                            // handle our custom syscalls
                            match (raw_nr, raw_args) {
                                (0xff77, ..) => {
                                    info!("Checkpoint requested by {}", pid);
                                    check_coord.handle_checkpoint(pid, false);
                                }
                                (0xff78, ..) => {
                                    info!("Checkpoint finish requested by {}", pid);
                                    check_coord.handle_checkpoint(pid, true);
                                }
                                (0xff79, [base_address, ..]) => {
                                    assert!(pid == check_coord.main.pid);
                                    info!(
                                        "Set client control base address {:p} requested",
                                        base_address as *const u8
                                    );
                                    check_coord.set_client_control_addr(base_address as _);
                                    ptrace::syscall(pid, None).unwrap();
                                }
                                (0xff7a, ..) => {
                                    if pid == check_coord.main.pid {
                                        info!("Sync requested by main");
                                        check_coord.handle_sync();
                                    }
                                }
                                _ => {
                                    ptrace::syscall(pid, None).unwrap();
                                }
                            }
                            last_syscall_entry_handled_by_check_coord.insert(pid, false);
                        }
                    }
                    ptrace::SyscallInfoOp::Exit { ret_val, .. } => {
                        if *last_syscall_entry_handled_by_check_coord
                            .get(&pid)
                            .unwrap_or(&false)
                        {
                            check_coord.handle_syscall_exit(pid, ret_val as _);
                        } else {
                            ptrace::syscall(pid, None).unwrap();
                        }
                    }
                    _ => {
                        ptrace::syscall(pid, None).unwrap();
                    }
                }

                if pid == check_coord.main.pid {
                    syscall_cnt += 1;
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

    syscall_cnt /= 2;

    let all_exec_time = exec_start_time.elapsed();

    if flags.contains(RunnerFlags::DUMP_STATS) || stats_output.is_some() {
        let nr_checkpoints = check_coord.epoch();

        let mut s = [
            format!("main_exec_time={}", main_exec_time.as_secs_f64()),
            format!("all_exec_time={}", all_exec_time.as_secs_f64()),
            format!("nr_checkpoints={}", nr_checkpoints),
            format!(
                "avg_checkpoint_freq={}",
                (nr_checkpoints as f64) / main_exec_time.as_secs_f64()
            ),
            format!("avg_nr_dirty_pages={}", check_coord.avg_nr_dirty_pages()),
            format!("syscall_cnt={}", syscall_cnt),
        ]
        .join("\n");

        s.push_str("\n");

        if let Some(output_path) = stats_output {
            fs::write(output_path, s).unwrap();
        } else {
            print!("{}", s);
        }
    }

    exit_status.unwrap()
}

fn run(
    cmd: &mut Command,
    checker_cpu_set: &Vec<usize>,
    main_cpu_set: &Vec<usize>,
    runner_flags: RunnerFlags,
    check_coord_flags: CheckCoordinatorFlags,
    checkpoint_freq: u32,
    stats_output: Option<PathBuf>,
    max_nr_live_segments: usize,
) -> i32 {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent_work(
            child,
            checker_cpu_set,
            main_cpu_set,
            runner_flags,
            check_coord_flags,
            stats_output,
            max_nr_live_segments,
        ),
        Ok(ForkResult::Child) => {
            let err = unsafe {
                cmd.env("CHECKER_CHECKPOINT_FREQ", checkpoint_freq.to_string())
                    .pre_exec(|| {
                        raise(Signal::SIGSTOP).unwrap();
                        Ok(())
                    })
                    .exec()
            };
            panic!("failed to spawn subcommand: {:?}", err)
        }
        Err(err) => panic!("Fork failed: {}", err),
    }
}

#[tokio::main]
async fn main() -> ExitCode {
    #[cfg(feature = "compel")]
    compel::log_init(log::Level::Error);

    let cli = CliArgs::parse();

    if let Some(log_output) = cli.log_output {
        let log_file = Box::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(log_output)
                .expect("Can't create file"),
        );

        env_logger::Builder::new()
            .parse_default_env()
            .target(env_logger::Target::Pipe(log_file))
            .init();

        log_panics::init();
    } else {
        env_logger::init();
    }

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
    check_coord_flags.set(CheckCoordinatorFlags::DONT_FORK, cli.dont_fork);
    check_coord_flags.set(
        CheckCoordinatorFlags::IGNORE_CHECK_ERRORS,
        cli.ignore_check_errors,
    );

    #[cfg(feature = "compel")]
    check_coord_flags.set(CheckCoordinatorFlags::USE_LIBCOMPEL, cli.use_libcompel);

    let exit_status = run(
        Command::new(cli.command).args(cli.args),
        &cli.checker_cpu_set,
        &cli.main_cpu_set,
        runner_flags,
        check_coord_flags,
        cli.checkpoint_freq,
        cli.stats_output,
        cli.max_nr_live_segments,
    );

    ExitCode::from(exit_status as u8)
}

#[cfg(test)]
mod tests {
    use super::*;
    use serial_test::serial;
    use tempfile::TempDir;

    use std::path::Path;

    fn compile(filename: &'static str) -> (&'static str, TempDir) {
        let out_dir = tempfile::tempdir().unwrap();

        let output = filename.strip_suffix(".c").unwrap();

        let exit_code = Command::new("cc")
            .arg("-O0")
            .arg(Path::new("./tests").join(filename))
            .arg("-o")
            .arg(out_dir.path().join(output))
            .status()
            .unwrap();

        assert!(exit_code.success());

        (output, out_dir)
    }

    fn run_reldrv(cmd: &mut Command) -> i32 {
        run(
            cmd,
            &vec![],
            &vec![],
            RunnerFlags::empty(),
            CheckCoordinatorFlags::empty(),
            0,
            None,
            8,
        )
    }

    #[tokio::test]
    #[serial] // we don't allow a single tracer to trace multiple processes
    async fn test_syscall_replication_handling() {
        let (output, out_dir) = compile("syscall_brk.c");
        let exit_code = run_reldrv(&mut Command::new(out_dir.path().join(output)));
        assert_eq!(exit_code, 0)
    }

    #[tokio::test]
    #[serial]
    async fn test_syscall_memrw_handling_read_write() {
        let (output, out_dir) = compile("syscall_read_write.c");
        let exit_code = run_reldrv(&mut Command::new(out_dir.path().join(output)));
        assert_eq!(exit_code, 0)
    }

    #[tokio::test]
    #[serial]
    async fn test_syscall_memrw_handling_getpid() {
        let (output, out_dir) = compile("syscall_getpid.c");
        let exit_code = run_reldrv(&mut Command::new(out_dir.path().join(output)));
        assert_eq!(exit_code, 0)
    }

    #[tokio::test]
    #[serial]
    async fn test_syscall_mmap_handling() {
        let (output, out_dir) = compile("syscall_mmap.c");
        let exit_code = run_reldrv(&mut Command::new(out_dir.path().join(output)));
        assert_eq!(exit_code, 0)
    }

    // #[tokio::test]
    // #[serial]
    // async fn test_syscall_mremap_handling() {
    //     let (output, out_dir) = compile("syscall_mremap.c");
    //     let exit_code = run_reldrv(&mut Command::new(out_dir.path().join(output)));
    //     assert_eq!(exit_code, 0)
    // }

    #[tokio::test]
    #[serial]
    #[should_panic]
    async fn test_syscall_unknown_memrw_handling() {
        let (output, out_dir) = compile("unknown_memrw.c");
        run_reldrv(&mut Command::new(out_dir.path().join(output)));
    }

    #[tokio::test]
    #[serial]
    async fn test_duplicated_checkpoint_fini() {
        let (output, out_dir) = compile("ckpt_duplicated_fini.c");
        run_reldrv(&mut Command::new(out_dir.path().join(output)));
    }

    #[tokio::test]
    #[serial]
    async fn test_no_checkpoint_fini() {
        // if checkpoint_fini is not called explicitly by the user program, reldrv should make a finalizing checkpoint automatically on main exit.
        let (output, out_dir) = compile("ckpt_no_fini.c");
        run_reldrv(&mut Command::new(out_dir.path().join(output)));
    }

    // // below is unreliable as some systems do not have vdso
    // #[tokio::test]
    // #[serial]
    // #[should_panic]
    // async fn test_vdso_handling() {
    //     // we don't support vdso handling now
    //     let (output, out_dir) = compile("syscall_clock_gettime.c");
    //     run_reldrv(&mut Command::new(out_dir.path().join(output)));
    // }
}
