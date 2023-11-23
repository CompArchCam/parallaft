use std::fs::OpenOptions;
use std::os::unix::process::CommandExt;
use std::panic;
use std::path::PathBuf;
use std::process::Command;

use nix::sys::signal::{raise, Signal};
use nix::unistd::{fork, ForkResult};

use clap::Parser;
use clap_num::maybe_hex;

use reldrv::{
    check_coord::CheckCoordinatorFlags, parent_work, statistics::perf::CounterKind,
    RelShellOptions, RunnerFlags,
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

    /// Shell CPU set
    #[arg(short, long, use_value_delimiter = true)]
    shell_cpu_set: Vec<usize>,

    #[cfg(feature = "intel_cat")]
    /// Cache allocation masks for the main process. Intel only.
    #[arg(long, value_parser=maybe_hex::<u32>)]
    main_cache_mask: Option<u32>,

    #[cfg(feature = "intel_cat")]
    /// Cache allocation Mask for checker processes. Intel only.
    #[arg(long, value_parser=maybe_hex::<u32>)]
    checker_cache_mask: Option<u32>,

    #[cfg(feature = "intel_cat")]
    /// Cache allocation mask for the shell processes. Intel only.
    #[arg(long, value_parser=maybe_hex::<u32>)]
    shell_cache_mask: Option<u32>,

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

    /// Ignore check errors.
    #[arg(long)]
    ignore_check_errors: bool,

    /// Don't collect number of dirty pages information.
    /// Collecting them is expensive.
    #[arg(long)]
    no_nr_dirty_pages_logging: bool,

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

    /// Maximum number of live segments (0 = unlimited).
    #[arg(long, default_value_t = 8)]
    max_nr_live_segments: usize,

    /// Memory overhead limit in bytes (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    max_memory_overhead: usize,

    /// Checkpoint size watermark in number of pages (0 = unlimited).
    #[arg(long, default_value_t = 0)]
    checkpoint_size_watermark: usize,

    /// Pause on panic (e.g. when errors are detected), instead of aborting.
    #[arg(long)]
    pause_on_panic: bool,

    /// Checkpoint period in number of instructions. Used by librelrt and PMU-based segmentor.
    #[arg(long, default_value_t = 1000000000)]
    checkpoint_period: u64,

    /// Perf counters to sample during the inferior execution.
    #[arg(long, use_value_delimiter = true)]
    enabled_perf_counters: Vec<CounterKind>,

    /// Automatic segmentation based precise PMU interrupts. Conflicts with relrtlibs.
    #[arg(short, long)]
    pmu_segmentation: bool,

    command: String,
    args: Vec<String>,
}

fn run(cmd: &mut Command, options: RelShellOptions) -> i32 {
    match unsafe { fork() } {
        Ok(ForkResult::Parent { child }) => parent_work(child, options),
        Ok(ForkResult::Child) => {
            let err = unsafe {
                cmd.pre_exec(move || {
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
    check_coord_flags.set(
        CheckCoordinatorFlags::NO_NR_DIRTY_PAGES_LOGGING,
        cli.no_nr_dirty_pages_logging,
    );

    assert!(
        (cli.main_cache_mask.is_none() && cli.checker_cache_mask.is_none() && cli.shell_cache_mask.is_none())
            || (cli.main_cache_mask.is_some() && cli.checker_cache_mask.is_some() && cli.shell_cache_mask.is_some()),
        "You may only specify none of all of main_cache_mask, checker_cache_mask, and shell_cache_mask"
    );

    let exit_status = run(
        Command::new(cli.command).args(cli.args),
        RelShellOptions {
            runner_flags,
            check_coord_flags,
            stats_output: cli.stats_output,
            checkpoint_period: cli.checkpoint_period,
            max_nr_live_segments: cli.max_nr_live_segments,
            memory_overhead_watermark: cli.max_memory_overhead,
            main_cpu_set: cli.main_cpu_set,
            checker_cpu_set: cli.checker_cpu_set,
            shell_cpu_set: cli.shell_cpu_set,
            checkpoint_size_watermark: cli.checkpoint_size_watermark,
            cache_masks: cli.main_cache_mask.and_then(|main_cache_mask| {
                cli.checker_cache_mask.and_then(|checker_cache_mask| {
                    cli.shell_cache_mask.map(|shell_cache_mask| {
                        (main_cache_mask, checker_cache_mask, shell_cache_mask)
                    })
                })
            }),
            enabled_perf_counters: cli.enabled_perf_counters,
            pmu_segmentation: cli.pmu_segmentation,
        },
    );

    std::process::exit(exit_status as _);
}
