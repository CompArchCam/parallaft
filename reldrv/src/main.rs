mod check_coord;
mod inferior_rtlib;

mod dispatcher;
mod process;
mod saved_syscall;
mod segments;
mod signal_handlers;
mod stats;
mod syscall_handlers;

use std::collections::HashMap;
use std::fs::{self, OpenOptions};
use std::os::unix::process::CommandExt;
use std::panic;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use bitflags::bitflags;

use nix::errno::Errno;

use nix::sys::ptrace::{self, SyscallInfoOp};
use nix::sys::signal::{raise, Signal};

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

use clap::Parser;

use log::{info, warn};

use crate::check_coord::{
    CheckCoordinator, CheckCoordinatorFlags, CheckCoordinatorHooks, CheckCoordinatorOptions,
};
use crate::dispatcher::{Dispatcher, Installable};
use crate::inferior_rtlib::legacy::LegacyInferiorRtLib;
use crate::inferior_rtlib::relrtlib::RelRtLib;
use crate::process::{OwnedProcess, Process};
use crate::segments::CheckpointCaller;
use crate::signal_handlers::cpuid::CpuidHandler;
use crate::signal_handlers::rdtsc::RdtscHandler;
use crate::syscall_handlers::clone::CloneHandler;
use crate::syscall_handlers::execve::ExecveHandler;
use crate::syscall_handlers::exit::ExitHandler;
use crate::syscall_handlers::replicate::ReplicatedSyscallHandler;
use crate::syscall_handlers::rseq::RseqHandler;
use crate::syscall_handlers::{
    CustomSyscallHandler, HandlerContext, MainInitHandler, SyscallHandlerExitAction,
};

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

    /// Dump statistics.
    #[arg(long)]
    dump_stats: bool,

    #[cfg(target_arch = "x86_64")]
    /// Don't trap rdtsc instructions.
    #[arg(long)]
    dont_trap_rdtsc: bool,

    #[cfg(target_arch = "x86_64")]
    /// Don't trap cpuid instructions.
    #[arg(long)]
    dont_trap_cpuid: bool,

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

    /// Pause on panic (e.g. when errors are detected), instead of aborting.
    #[arg(long)]
    pause_on_panic: bool,

    /// librelrt Checkpoint period in number of instructions.
    #[arg(long, default_value_t = 1000000000)]
    librelrt_checkpoint_period: u64,

    command: String,
    args: Vec<String>,
}

bitflags! {
    struct RunnerFlags: u32 {
        const POLL_WAITPID = 0b00000001;
        const DUMP_STATS = 0b00000010;
        const DONT_TRAP_RDTSC = 0b00000100;
        const DONT_TRAP_CPUID = 0b00001000;
    }
}

fn parent_work(
    child_pid: Pid,
    checker_cpu_set: Vec<usize>,
    main_cpu_set: Vec<usize>,
    flags: RunnerFlags,
    check_coord_options: CheckCoordinatorOptions,
    stats_output: Option<PathBuf>,
    librelrt_checkpoint_period: u64,
) -> i32 {
    info!("Starting");

    let status = waitpid(child_pid, Some(WaitPidFlag::WSTOPPED)).unwrap();
    assert_eq!(status, WaitStatus::Stopped(child_pid, Signal::SIGSTOP));
    ptrace::seize(
        child_pid,
        ptrace::Options::PTRACE_O_TRACESYSGOOD
            | ptrace::Options::PTRACE_O_TRACECLONE
            | ptrace::Options::PTRACE_O_TRACEFORK
            | ptrace::Options::PTRACE_O_EXITKILL
            | ptrace::Options::PTRACE_O_ALLOW_TRACER_THREAD_GROUP,
    )
    .unwrap();

    let mut disp = Dispatcher::new();
    let rseq_handler = RseqHandler::new();
    rseq_handler.install(&mut disp);

    let clone_handler = CloneHandler::new();
    clone_handler.install(&mut disp);

    let execve_handler = ExecveHandler::new();
    execve_handler.install(&mut disp);

    let exit_handler = ExitHandler::new();
    exit_handler.install(&mut disp);

    let replicated_syscall_handler = ReplicatedSyscallHandler::new();
    replicated_syscall_handler.install(&mut disp);

    let rdtsc_handler = RdtscHandler::new();

    if !flags.contains(RunnerFlags::DONT_TRAP_RDTSC) {
        rdtsc_handler.install(&mut disp);
    }

    let cpuid_handler = CpuidHandler::new();

    if !flags.contains(RunnerFlags::DONT_TRAP_CPUID) {
        cpuid_handler.install(&mut disp);
    }

    let legacy_rtlib_handler = LegacyInferiorRtLib::new();
    legacy_rtlib_handler.install(&mut disp);

    let relrtlib_handler = RelRtLib::new(librelrt_checkpoint_period);
    relrtlib_handler.install(&mut disp);

    info!("Child process tracing started");

    let inferior = OwnedProcess::new(child_pid);

    disp.handle_main_init(&inferior);

    let check_coord = CheckCoordinator::new(
        inferior,
        check_coord_options,
        CheckCoordinatorHooks::default()
            .with_on_checker_created(move |process| process.set_cpu_affinity(&checker_cpu_set)),
        &disp,
    );

    check_coord.main.set_cpu_affinity(&main_cpu_set);
    check_coord.main.resume();

    let mut main_finished = false;
    let mut main_exec_time = Duration::ZERO;

    let exec_start_time = Instant::now();
    let mut syscall_cnt = 0;

    let mut last_syscall_entry_handled_by_check_coord: HashMap<Pid, bool> = HashMap::new();

    let mut exit_status = None;

    loop {
        let status = waitpid(
            None,
            if flags.contains(RunnerFlags::POLL_WAITPID) {
                Some(WaitPidFlag::WNOHANG)
            } else {
                None
            },
        )
        .unwrap();

        match status {
            WaitStatus::Stopped(pid, sig) => {
                check_coord.handle_signal(pid, sig);
            }
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

                let process = Process::new(pid);
                let regs = process.read_registers();

                if matches!(syscall_info.op, SyscallInfoOp::Entry { .. }) {
                    // syscall entry

                    if let Some(sysno) = regs.sysno() {
                        let args = regs.syscall_args();
                        check_coord.handle_syscall_entry(pid, sysno, args);
                        last_syscall_entry_handled_by_check_coord.insert(pid, true);
                    } else {
                        let handled = disp.handle_custom_syscall_entry(
                            regs.sysno_raw(),
                            regs.syscall_args(),
                            &HandlerContext {
                                process: &process,
                                check_coord: &check_coord,
                            },
                        );

                        if matches!(handled, SyscallHandlerExitAction::NextHandler) {
                            // handle our custom syscalls
                            match (regs.sysno_raw(), regs.syscall_args()) {
                                (0xff77, ..) => {
                                    info!("Checkpoint requested by {}", pid);
                                    check_coord.handle_checkpoint(
                                        pid,
                                        false,
                                        false,
                                        CheckpointCaller::Child,
                                    );
                                }
                                (0xff78, ..) => {
                                    info!("Checkpoint finish requested by {}", pid);
                                    check_coord.handle_checkpoint(
                                        pid,
                                        true,
                                        false,
                                        CheckpointCaller::Child,
                                    );
                                }
                                (0xff79, ..) => {
                                    if pid == check_coord.main.pid {
                                        info!("Sync requested by main");
                                        check_coord.handle_sync();
                                    }
                                }
                                _ => {
                                    warn!("Unhandled syscall: {:x}", regs.sysno_raw());
                                    ptrace::syscall(pid, None).unwrap();
                                }
                            }
                        } else {
                            ptrace::syscall(pid, None).unwrap();
                        }

                        last_syscall_entry_handled_by_check_coord.insert(pid, false);
                    }
                } else {
                    // syscall exit
                    if *last_syscall_entry_handled_by_check_coord
                        .get(&pid)
                        .unwrap_or(&false)
                    {
                        check_coord.handle_syscall_exit(pid, regs.syscall_ret_val());
                    } else {
                        disp.handle_custom_syscall_exit(
                            regs.syscall_ret_val(),
                            &HandlerContext {
                                process: &process,
                                check_coord: &check_coord,
                            },
                        );

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
                if sig == Signal::SIGKILL {
                    if check_coord.has_errors() {
                        panic!("Memory check has errors");
                    }

                    if main_finished && check_coord.is_all_finished() {
                        break;
                    }
                } else {
                    panic!("PID {} signaled by {}", pid, sig);
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
    checker_cpu_set: Vec<usize>,
    main_cpu_set: Vec<usize>,
    runner_flags: RunnerFlags,
    check_coord_options: CheckCoordinatorOptions,
    checkpoint_freq: u32,
    stats_output: Option<PathBuf>,
    librelrt_checkpoint_period: u64,
) -> i32 {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent_work(
            child,
            checker_cpu_set,
            main_cpu_set,
            runner_flags,
            check_coord_options,
            stats_output,
            librelrt_checkpoint_period,
        ),
        Ok(ForkResult::Child) => {
            let err = unsafe {
                cmd.env("CHECKER_CHECKPOINT_FREQ", checkpoint_freq.to_string())
                    .pre_exec(move || {
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

fn main() {
    #[cfg(feature = "compel")]
    compel::log_init(log::Level::Error);

    let cli = CliArgs::parse();
    let pause_on_panic = cli.pause_on_panic;

    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        if pause_on_panic {
            raise(Signal::SIGSTOP).unwrap();
        }
        std::process::exit(1);
    }));

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
    runner_flags.set(RunnerFlags::DONT_TRAP_RDTSC, cli.dont_trap_rdtsc);
    runner_flags.set(RunnerFlags::DONT_TRAP_CPUID, cli.dont_trap_cpuid);

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

    let exit_status = run(
        Command::new(cli.command).args(cli.args),
        cli.checker_cpu_set,
        cli.main_cpu_set,
        runner_flags,
        CheckCoordinatorOptions {
            max_nr_live_segments: cli.max_nr_live_segments,
            flags: check_coord_flags,
        },
        cli.checkpoint_freq,
        cli.stats_output,
        cli.librelrt_checkpoint_period,
    );

    std::process::exit(exit_status as _);
}

#[cfg(test)]
mod tests {

    use super::*;

    use core::slice;
    use nix::{
        libc,
        sys::{
            memfd::{memfd_create, MemFdCreateFlag},
            mman, uio,
        },
        unistd::{self, getpid},
    };
    use serial_test::serial;
    use std::{
        arch::{
            asm,
            x86_64::{__cpuid_count, __rdtscp, _rdtsc},
        },
        ffi::CString,
        fs::File,
        io::IoSliceMut,
        mem::MaybeUninit,
        num::NonZeroUsize,
        os::fd::{AsRawFd, OwnedFd},
        sync::Once,
    };

    static INIT: Once = Once::new();

    fn setup() {
        INIT.call_once(|| {
            env_logger::builder().is_test(true).init();

            // let orig_hook = panic::take_hook();
            // panic::set_hook(Box::new(move |panic_info| {
            //     orig_hook(panic_info);
            //     std::process::exit(1);
            // }));
        });
    }

    fn trace(f: impl FnOnce() -> i32, options: CheckCoordinatorOptions) -> i32 {
        match unsafe { fork().unwrap() } {
            ForkResult::Parent { child } => parent_work(
                child,
                Vec::new(),
                Vec::new(),
                RunnerFlags::empty(),
                options,
                None,
                0,
            ),
            ForkResult::Child => {
                raise(Signal::SIGSTOP).unwrap();
                let code = f();
                std::process::exit(code);
            }
        }
    }

    fn checkpoint_take() {
        unsafe { libc::syscall(0xff77) };
    }

    fn checkpoint_fini() {
        unsafe { libc::syscall(0xff78) };
    }

    #[test]
    #[serial] // we don't allow a single tracer to trace multiple processes
    fn test_basic_checkpointing() {
        setup();

        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_max_nr_live_segments_limit_1() {
        setup();

        assert_eq!(
            trace(
                || {
                    for _ in 0..20 {
                        checkpoint_take();
                    }
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default().with_max_nr_live_segments(1)
            ),
            0
        );
    }

    #[test]
    #[serial]
    fn test_max_nr_live_segments_limit_8_getpid_loop() {
        setup();

        assert_eq!(
            trace(
                || {
                    for _ in 0..2000 {
                        checkpoint_take();
                        getpid();
                    }
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default().with_max_nr_live_segments(8)
            ),
            0
        );
    }

    #[test]
    #[serial]
    fn test_syscall_replication_handling_brk() {
        setup();
        assert_eq!(
            trace(
                || {
                    const LEN: usize = 16384;

                    checkpoint_take();

                    let ptr = unsafe { libc::sbrk(LEN as _) };
                    assert_ne!(ptr, -1_isize as *mut libc::c_void);

                    let s = unsafe { std::slice::from_raw_parts_mut(ptr as *mut u8, LEN) };

                    // ensure we can read and write without causing a segfault
                    s.fill(42);
                    assert!(s.iter().all(|&x| x == 42));

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        );
    }

    #[test]
    #[serial]
    fn test_syscall_getpid_loop() {
        setup();
        assert_eq!(
            trace(
                || {
                    let orig_pid = unsafe { libc::getpid() };

                    checkpoint_take();

                    for _ in 0..20 {
                        let pid = unsafe { libc::getpid() };
                        assert_eq!(pid, orig_pid);
                    }

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        );
    }

    #[test]
    #[serial]
    fn test_checkpoint_syscall_getpid_loop() {
        setup();
        assert_eq!(
            trace(
                || {
                    let orig_pid = unsafe { libc::getpid() };

                    for _ in 0..200 {
                        checkpoint_take();
                        let pid = unsafe { libc::getpid() };
                        assert_eq!(pid, orig_pid);
                    }

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        );
    }

    #[test]
    #[serial]
    fn test_no_checkpoint_fini() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        );
    }

    #[test]
    #[serial]
    fn test_duplicated_checkpoint_fini() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    checkpoint_fini();
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        );
    }

    #[test]
    #[serial]
    #[should_panic]
    fn test_syscall_fork() {
        setup();
        trace(
            || {
                match unsafe { fork().unwrap() } {
                    ForkResult::Parent { .. } => {
                        println!("You should not see this line");
                    }
                    ForkResult::Child => {
                        println!("You should not see this line");
                    }
                };
                0
            },
            CheckCoordinatorOptions::default(),
        );
    }

    #[test]
    #[serial]
    fn test_syscall_exit() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    unsafe { libc::syscall(libc::SYS_exit, 42) };
                    unreachable!()
                },
                CheckCoordinatorOptions::default()
            ),
            42
        );
    }

    #[test]
    #[serial]
    fn test_syscall_exit_group() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    unsafe { libc::syscall(libc::SYS_exit_group, 42) };
                    unreachable!()
                },
                CheckCoordinatorOptions::default()
            ),
            42
        );
    }

    #[test]
    #[serial]
    fn test_syscall_read_write() {
        setup();
        assert_eq!(
            trace(
                || {
                    let (rx, tx) = unistd::pipe().unwrap();

                    checkpoint_take();

                    let data = [0, 1, 2, 3, 4, 5, 6, 7];
                    unistd::write(tx, &data).unwrap();

                    let mut buf = [0u8; 4];
                    unistd::read(rx, &mut buf).unwrap();
                    assert_eq!(buf, data[..4]);
                    unistd::read(rx, &mut buf).unwrap();
                    assert_eq!(buf, data[4..]);

                    unistd::close(rx).unwrap();
                    unistd::close(tx).unwrap();

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_mmap_anon() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();

                    const LEN: usize = 4096 * 4;

                    let addr = unsafe {
                        mman::mmap::<OwnedFd>(
                            None,
                            NonZeroUsize::new(LEN).unwrap(),
                            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                            mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                            None,
                            0,
                        )
                        .unwrap()
                    };

                    let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

                    // ensure we can read and write the mremap-ped memory
                    arr.fill(42);
                    assert!(arr.iter().all(|&x| x == 42));

                    unsafe { mman::munmap(addr, LEN).unwrap() };

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_mmap_fd_read_dev_zero() {
        setup();
        assert_eq!(
            trace(
                || {
                    let file = File::open("/dev/zero").unwrap();
                    const LEN: usize = 4096 * 4;

                    checkpoint_take();

                    let addr = unsafe {
                        mman::mmap(
                            None,
                            NonZeroUsize::new(LEN).unwrap(),
                            mman::ProtFlags::PROT_READ,
                            mman::MapFlags::MAP_PRIVATE,
                            Some(&file),
                            0,
                        )
                        .unwrap()
                    };

                    let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };
                    assert!(arr.iter().all(|&x| x == 0));

                    unsafe { mman::munmap(addr, LEN).unwrap() };

                    drop(file);

                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_mmap_fd_read_memfd() {
        setup();
        assert_eq!(
            trace(
                || {
                    let fd = memfd_create(
                        &CString::new("reldrv-test").unwrap(),
                        MemFdCreateFlag::empty(),
                    )
                    .unwrap();

                    const LEN: usize = 4096 * 4;
                    unistd::write(fd.as_raw_fd(), &[42u8; LEN]).unwrap();

                    checkpoint_take();

                    let addr = unsafe {
                        mman::mmap(
                            None,
                            NonZeroUsize::new(LEN).unwrap(),
                            mman::ProtFlags::PROT_READ,
                            mman::MapFlags::MAP_PRIVATE,
                            Some(&fd),
                            0,
                        )
                        .unwrap()
                    };

                    let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

                    assert!(arr.iter().all(|&x| x == 42));

                    unsafe { mman::munmap(addr, LEN).unwrap() };

                    drop(fd);

                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_mmap_fd_write_shared_memfd() {
        // TODO: incomplete implementation: changes to writable and shared mmap regions do not propagate to fds
        setup();
        assert_eq!(
            trace(
                || {
                    let fd = memfd_create(
                        &CString::new("reldrv-test").unwrap(),
                        MemFdCreateFlag::empty(),
                    )
                    .unwrap();

                    const LEN: usize = 4096 * 4;
                    unistd::write(fd.as_raw_fd(), &[0u8; LEN]).unwrap();

                    checkpoint_take();

                    let addr = unsafe {
                        mman::mmap(
                            None,
                            NonZeroUsize::new(LEN).unwrap(),
                            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                            mman::MapFlags::MAP_SHARED,
                            Some(&fd),
                            0,
                        )
                        .unwrap()
                    };

                    let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

                    assert!(arr.iter().all(|&x| x == 0));

                    arr.fill(42);

                    assert!(arr.iter().all(|&x| x == 42));

                    unsafe { mman::munmap(addr, LEN).unwrap() };

                    drop(fd);

                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    // TODO: test MAP_SHARED-to-MAP_PRIVATE transformation

    #[test]
    #[serial]
    fn test_syscall_mremap_maymove() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();

                    const LEN: usize = 4096 * 4;
                    const NEW_LEN: usize = 4096 * 8;

                    let addr = unsafe {
                        mman::mmap::<OwnedFd>(
                            None,
                            NonZeroUsize::new(LEN).unwrap(),
                            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                            mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                            None,
                            0,
                        )
                        .unwrap()
                    };

                    let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

                    // ensure we can write the mmap-ped memory
                    arr.fill(42);

                    let addr_new = unsafe {
                        mman::mremap(addr, LEN, NEW_LEN, mman::MRemapFlags::MREMAP_MAYMOVE, None)
                            .unwrap()
                    };

                    let arr_new =
                        unsafe { slice::from_raw_parts_mut(addr_new as *mut u8, NEW_LEN) };

                    // ensure we can read and write the mmap-ped memory
                    arr_new.fill(84);
                    arr_new.iter().all(|&x| x == 84);

                    unsafe { mman::munmap(addr, LEN).unwrap() };

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_mremap_may_not_move() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();

                    const LEN: usize = 4096 * 4;
                    const NEW_LEN: usize = 4096 * 2;

                    let addr = unsafe {
                        mman::mmap::<OwnedFd>(
                            None,
                            NonZeroUsize::new(LEN).unwrap(),
                            mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                            mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                            None,
                            0,
                        )
                        .unwrap()
                    };

                    let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

                    // ensure we can write the mmap-ped memory
                    arr.fill(42);

                    let addr_new = unsafe {
                        mman::mremap(addr, LEN, NEW_LEN, mman::MRemapFlags::empty(), None).unwrap()
                    };

                    let arr_new =
                        unsafe { slice::from_raw_parts_mut(addr_new as *mut u8, NEW_LEN) };

                    // ensure we can read and write the mmap-ped memory
                    arr_new.fill(84);
                    arr_new.iter().all(|&x| x == 84);

                    unsafe { mman::munmap(addr, NEW_LEN).unwrap() };

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    #[should_panic]
    fn test_syscall_unsupported() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    let fd = File::open("/dev/zero").unwrap();
                    let mut buf = [0u8; 16];
                    uio::readv(fd, &mut [IoSliceMut::new(&mut buf)]).unwrap();
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtsc() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    let _tsc = unsafe { _rdtsc() };
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtsc_loop() {
        setup();
        assert_eq!(
            trace(
                || {
                    let mut prev_tsc: u64 = 0;
                    checkpoint_take();

                    for _ in 0..1000 {
                        let tsc = unsafe { _rdtsc() };
                        assert!(tsc > prev_tsc);
                        prev_tsc = tsc;
                    }

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtsc_outside_protected_region() {
        setup();
        assert_eq!(
            trace(
                || {
                    unsafe { _rdtsc() };
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtscp() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    let mut aux = MaybeUninit::uninit();
                    let _tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
                    let _aux = unsafe { aux.assume_init() };
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtscp_loop() {
        setup();
        assert_eq!(
            trace(
                || {
                    let mut prev_tsc: u64 = 0;
                    checkpoint_take();

                    for _ in 0..1000 {
                        let mut aux = MaybeUninit::uninit();
                        let tsc = unsafe { __rdtscp(aux.as_mut_ptr()) };
                        assert!(tsc > prev_tsc);
                        prev_tsc = tsc;
                    }

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    #[should_panic] // trapping RDPID isn't supported at the moment
    fn test_rdpid() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();

                    let _processor_id: u64;
                    unsafe {
                        asm!(
                            "rdpid rax",
                            out("rax") _processor_id,
                        );
                    }

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtscp_outside_protected_region() {
        setup();
        assert_eq!(
            trace(
                || {
                    let mut aux = MaybeUninit::uninit();
                    unsafe { __rdtscp(aux.as_mut_ptr()) };
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_cpuid() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    unsafe {
                        __cpuid_count(0, 0);
                        __cpuid_count(1, 0);
                        __cpuid_count(2, 0);
                        __cpuid_count(3, 0);
                        __cpuid_count(6, 0);
                        __cpuid_count(7, 0);
                        __cpuid_count(7, 1);
                        __cpuid_count(7, 2);
                    }
                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default(),
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_clock_gettime() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();
                    let mut t = MaybeUninit::<libc::timespec>::uninit();

                    unsafe {
                        libc::syscall(
                            libc::SYS_clock_gettime,
                            libc::CLOCK_MONOTONIC,
                            t.as_mut_ptr(),
                        )
                    };

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    // #[test]
    // #[serial]
    // fn test_syscall_getcpu() {
    //     setup();
    //     assert_eq!(
    //         trace(|| {
    //             checkpoint_take();

    //             for _ in 0..10000 {
    //                 let _c = unsafe { libc::sched_getcpu() };
    //                 unsafe { libc::sched_yield() }; // yield to another cpu
    //             }

    //             checkpoint_fini();
    //             0
    //         }),
    //         0
    //     )
    // }

    #[test]
    #[serial]
    #[should_panic]
    fn test_syscall_fork_in_protected_region() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();

                    unsafe { fork().unwrap() };

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    #[should_panic]
    fn test_syscall_execve() {
        setup();
        assert_eq!(
            trace(
                || {
                    checkpoint_take();

                    Command::new("/usr/bin/true").exec();

                    checkpoint_fini();
                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }

    #[test]
    #[serial]
    fn test_register_preservation_after_checkpoint() {
        setup();
        assert_eq!(
            trace(
                || {
                    let result: u64;

                    unsafe {
                        asm!(
                            "
                            mov rdi, 12345
                            push rbx
                            push rdx
                            push rsi
                            push rdi
                            push r8
                            push r9
                            push r10
                            push r12
                            push r13
                            push r14
                            push r15
                            pushfq

                            mov rax, 0xff77
                            syscall

                            pushfq
                            pop rax
                            pop r11
                            cmp rax, r11
                            jne 1f

                            pop rax
                            cmp rax, r15
                            jne 1f

                            pop rax
                            cmp rax, r14
                            jne 1f

                            pop rax
                            cmp rax, r13
                            jne 1f

                            pop rax
                            cmp rax, r12
                            jne 1f

                            pop rax
                            cmp rax, r10
                            jne 1f

                            pop rax
                            cmp rax, r9
                            jne 1f

                            pop rax
                            cmp rax, r8
                            jne 1f

                            pop rax
                            cmp rax, rdi
                            jne 1f

                            pop rax
                            cmp rax, rsi
                            jne 1f

                            pop rax
                            cmp rax, rdx
                            jne 1f

                            pop rax
                            cmp rax, rbx
                            jne 1f

                            mov rax, 0
                            jmp 2f
                            1:
                            mov rax, 1
                            2:
                            ",
                            out("rcx") _,
                            out("r11") _,
                            out("rdi") _,
                            lateout("rax") result,
                        )
                    }

                    if result == 1 {
                        return 1;
                    }

                    0
                },
                CheckCoordinatorOptions::default()
            ),
            0
        )
    }
}
