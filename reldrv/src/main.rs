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
use std::panic;
use std::path::PathBuf;
use std::process::Command;
use std::time::{Duration, Instant};

use bitflags::bitflags;
use nix::errno::Errno;

use nix::libc;
use nix::sys::ptrace;
use nix::sys::signal::{raise, Signal};

use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{fork, ForkResult, Pid};

use clap::Parser;

use log::info;

use crate::checkpoint::{CheckCoordinator, CheckCoordinatorFlags};
use crate::process::{OwnedProcess};

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

fn parent_work(
    child_pid: Pid,
    checker_cpu_set: &Vec<usize>,
    main_cpu_set: &Vec<usize>,
    flags: RunnerFlags,
    check_coord_flags: CheckCoordinatorFlags,
    stats_output: Option<PathBuf>,
    max_nr_live_segments: usize,
    is_test: bool, // remove already-registered rseq in tests
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

    let mut rseq_configuration = if is_test {
        ptrace::get_rseq_configuration(child_pid)
            .ok()
            .and_then(|c| {
                if c.rseq_abi_pointer == 0 {
                    None
                } else {
                    Some(c)
                }
            })
    } else {
        None
    };

    info!("Child process tracing started");

    let check_coord = CheckCoordinator::new(
        OwnedProcess::new(child_pid),
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

                match syscall_info.op {
                    ptrace::SyscallInfoOp::Entry {
                        nr: raw_nr,
                        args: raw_args,
                    } => {
                        // unregister rseq
                        if pid == check_coord.main.pid {
                            if let Some(rseq_configuration) = rseq_configuration.take() {
                                let ret = check_coord.main.syscall_direct(
                                    syscalls::Sysno::rseq,
                                    syscalls::syscall_args!(
                                        rseq_configuration.rseq_abi_pointer as _,
                                        rseq_configuration.rseq_abi_size as _,
                                        1,
                                        rseq_configuration.signature as _
                                    ),
                                    true,
                                    false,
                                );
                                assert_eq!(ret, 0);
                            }
                        }

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
                                    check_coord.handle_checkpoint(pid, false, false);
                                }
                                (0xff78, ..) => {
                                    info!("Checkpoint finish requested by {}", pid);
                                    check_coord.handle_checkpoint(pid, true, false);
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

                if check_coord.has_errors() {
                    panic!("Memory check has errors");
                }

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
            false,
        ),
        Ok(ForkResult::Child) => {
            let err = unsafe {
                cmd.env("CHECKER_CHECKPOINT_FREQ", checkpoint_freq.to_string())
                    .pre_exec(|| {
                        assert_eq!(libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV), 0);
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

    let orig_hook = panic::take_hook();
    panic::set_hook(Box::new(move |panic_info| {
        orig_hook(panic_info);
        std::process::exit(1);
    }));

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

    std::process::exit(exit_status as _);
}

#[cfg(test)]
mod tests {

    use super::*;

    use core::slice;
    use nix::{
        libc,
        sys::{mman, uio},
        unistd::{self},
    };
    use serial_test::serial;
    use std::{
        arch::x86_64::_rdtsc, fs::File, io::IoSliceMut, mem::MaybeUninit, num::NonZeroUsize,
        os::fd::OwnedFd, sync::Once,
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

    fn trace(f: impl FnOnce() -> i32) -> i32 {
        match unsafe { fork().unwrap() } {
            ForkResult::Parent { child } => parent_work(
                child,
                &Vec::new(),
                &Vec::new(),
                RunnerFlags::empty(),
                CheckCoordinatorFlags::empty(),
                None,
                0,
                true,
            ),
            ForkResult::Child => {
                assert_eq!(
                    unsafe { libc::prctl(libc::PR_SET_TSC, libc::PR_TSC_SIGSEGV) },
                    0
                );
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
            trace(|| {
                checkpoint_take();
                checkpoint_fini();
                0
            }),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_replication_handling_brk() {
        setup();
        assert_eq!(
            trace(|| {
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
            }),
            0
        );
    }

    #[test]
    #[serial]
    fn test_syscall_getpid_loop() {
        setup();
        assert_eq!(
            trace(|| {
                let orig_pid = unsafe { libc::getpid() };

                checkpoint_take();

                for _ in 0..20 {
                    let pid = unsafe { libc::getpid() };
                    assert_eq!(pid, orig_pid);
                }

                checkpoint_fini();
                0
            }),
            0
        );
    }

    #[test]
    #[serial]
    fn test_checkpoint_syscall_getpid_loop() {
        setup();
        assert_eq!(
            trace(|| {
                let orig_pid = unsafe { libc::getpid() };

                for _ in 0..200 {
                    checkpoint_take();
                    let pid = unsafe { libc::getpid() };
                    assert_eq!(pid, orig_pid);
                }

                checkpoint_fini();
                0
            }),
            0
        );
    }

    #[test]
    #[serial]
    fn test_no_checkpoint_fini() {
        setup();
        assert_eq!(
            trace(|| {
                checkpoint_take();
                0
            }),
            0
        );
    }

    #[test]
    #[serial]
    fn test_duplicated_checkpoint_fini() {
        setup();
        assert_eq!(
            trace(|| {
                checkpoint_take();
                checkpoint_fini();
                checkpoint_fini();
                0
            }),
            0
        );
    }

    #[test]
    #[serial]
    #[should_panic]
    fn test_syscall_fork() {
        setup();
        trace(|| {
            match unsafe { fork().unwrap() } {
                ForkResult::Parent { .. } => {
                    println!("You should not see this line");
                }
                ForkResult::Child => {
                    println!("You should not see this line");
                }
            };
            0
        });
    }

    #[test]
    #[serial]
    fn test_syscall_exit() {
        setup();
        assert_eq!(
            trace(|| {
                checkpoint_take();
                unsafe { libc::syscall(libc::SYS_exit, 42) };
                unreachable!()
            }),
            42
        );
    }

    #[test]
    #[serial]
    fn test_syscall_exit_group() {
        setup();
        assert_eq!(
            trace(|| {
                checkpoint_take();
                unsafe { libc::syscall(libc::SYS_exit_group, 42) };
                unreachable!()
            }),
            42
        );
    }

    #[test]
    #[serial]
    fn test_syscall_read_write() {
        setup();
        assert_eq!(
            trace(|| {
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
            }),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_mmap() {
        setup();
        assert_eq!(
            trace(|| {
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
                arr.iter().all(|&x| x == 42);

                unsafe { mman::munmap(addr, LEN).unwrap() };

                checkpoint_fini();
                0
            }),
            0
        )
    }

    // TODO: test MAP_SHARED-to-MAP_PRIVATE transformation

    #[test]
    #[serial]
    fn test_syscall_mremap() {
        setup();
        assert_eq!(
            trace(|| {
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

                let arr_new = unsafe { slice::from_raw_parts_mut(addr_new as *mut u8, NEW_LEN) };

                // ensure we can read and write the mmap-ped memory
                arr_new.fill(84);
                arr_new.iter().all(|&x| x == 84);

                unsafe { mman::munmap(addr, LEN).unwrap() };

                checkpoint_fini();
                0
            }),
            0
        )
    }

    #[test]
    #[serial]
    #[should_panic]
    fn test_syscall_unsupported() {
        setup();
        assert_eq!(
            trace(|| {
                checkpoint_take();
                let fd = File::open("/dev/zero").unwrap();
                let mut buf = [0u8; 16];
                uio::readv(fd, &mut [IoSliceMut::new(&mut buf)]).unwrap();
                checkpoint_fini();
                0
            }),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtsc() {
        setup();
        assert_eq!(
            trace(|| {
                checkpoint_take();
                let _tsc = unsafe { _rdtsc() };
                checkpoint_fini();
                0
            }),
            0
        )
    }

    #[test]
    #[serial]
    fn test_rdtsc_loop() {
        setup();
        assert_eq!(
            trace(|| {
                let mut prev_tsc: u64 = 0;
                checkpoint_take();

                for _ in 0..1000 {
                    let tsc = unsafe { _rdtsc() };
                    assert!(tsc > prev_tsc);
                    prev_tsc = tsc;
                }

                checkpoint_fini();
                0
            }),
            0
        )
    }

    #[test]
    #[serial]
    fn test_syscall_clock_gettime() {
        setup();
        assert_eq!(
            trace(|| {
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
            }),
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
}
