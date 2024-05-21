use std::fs::OpenOptions;
use std::os::unix::process::CommandExt;
use std::panic;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use nix::sys::signal::{raise, Signal};
use nix::unistd::{fork, ForkResult};

use clap::Parser;
use clap_num::maybe_hex;
use git_version::git_version;

use reldrv::helpers::cpufreq::CpuFreqGovernor;
use reldrv::slicers::{ReferenceType, SlicerType};
use reldrv::types::exit_reason::ExitReason;
use reldrv::types::perf_counter::BranchCounterType;
use reldrv::StatsOutput;
use reldrv::{
    check_coord::CheckCoordinatorOptions, parent_work, statistics::perf::CounterKind,
    DirtyPageAddressTrackerType, RelShellOptions,
};
use syscalls::{syscall, Sysno};

#[derive(Parser, Debug)]
#[command(version = git_version!())]
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

    /// CPU frequency in kHz or governor "ondemand" to use for the main process. Requires `--main-cpu-set` set.
    #[arg(long)]
    main_cpu_freq_governor: Option<CpuFreqGovernor>,

    /// CPU frequency in kHz or governor "ondemand" to use for checker processes. Requires `--checker-cpu-set` set.
    #[arg(long)]
    checker_cpu_freq_governor: Option<CpuFreqGovernor>,

    /// CPU frequency in kHz or governor "ondemand" to use for the shell process. Requires `--shell-cpu-set` set.
    #[arg(long)]
    shell_cpu_freq_governor: Option<CpuFreqGovernor>,

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

    /// Checkpoint period in number of instructions. Used by librelrt and PMU-based segmentor.
    #[arg(short = 'P', long, default_value_t = 1000000000)]
    checkpoint_period: u64,

    /// Perf counters to sample during the inferior execution.
    #[arg(long, use_value_delimiter = true)]
    enabled_perf_counters: Vec<CounterKind>,

    /// Automatic segmentation based precise PMU interrupts. Conflicts with relrtlibs.
    #[arg(short, long)]
    pmu_segmentation: bool,

    /// In PMU-based segmentation, type of branch to count.
    #[arg(long, default_value = "all-excl-far")]
    pmu_segmentation_branch_type: BranchCounterType,

    /// Dirty page tracker to use
    #[arg(long, default_value = "soft-dirty")]
    dirty_page_tracker: DirtyPageAddressTrackerType,

    /// Enable on-demand fork (ODF)
    #[arg(long)]
    odf: bool,

    /// Sample memory usage
    #[arg(long)]
    sample_memory_usage: bool,

    /// Include runtime memory usage in memory usage sampling
    #[arg(long)]
    memory_sample_includes_rt: bool,

    /// Memory sample interval in milliseconds
    #[arg(long, value_parser = parse_duration, default_value = "500")]
    memory_sample_interval: Duration,

    /// Enable speculative store bypass misfeature
    #[arg(long)]
    enable_speculative_store_bypass_misfeature: bool,

    /// Enable indirect branch speculation misfeature
    #[arg(long)]
    enable_indirect_branch_speculation_misfeature: bool,

    #[cfg(target_arch = "x86_64")]
    /// Enable Intel hybrid CPU workaround
    #[arg(long)]
    enable_intel_hybrid_workaround: bool,

    /// Strategy to use for automatically slicing the inferior
    #[arg(short = 'S', long, default_value = "null")]
    slicer: SlicerType,

    #[arg(long)]
    fixed_interval_slicer_skip: Option<u64>,

    #[arg(long, default_value = "instructions")]
    fixed_interval_slicer_reference_type: ReferenceType,

    command: String,
    args: Vec<String>,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    Ok(std::time::Duration::from_millis(arg.parse()?))
}

fn run(cmd: &mut Command, options: RelShellOptions) -> ExitReason {
    if options.enable_odf {
        unsafe { syscall!(Sysno::prctl, 65, 0, 0, 0, 0) }
            .expect("Failed to initialise on-demand fork (ODF). Check your kernel support.");
    }

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

    let mut env_logger_builder = pretty_env_logger::formatted_timed_builder();

    env_logger_builder.parse_default_env();

    if let Some(log_output) = cli.log_output {
        let log_file = Box::new(
            OpenOptions::new()
                .append(true)
                .create(true)
                .open(log_output)
                .expect("Can't create file"),
        );

        env_logger_builder.target(pretty_env_logger::env_logger::Target::Pipe(log_file));

        log_panics::init();
    }

    env_logger_builder.init();

    assert!(
        (cli.main_cache_mask.is_none() && cli.checker_cache_mask.is_none() && cli.shell_cache_mask.is_none())
            || (cli.main_cache_mask.is_some() && cli.checker_cache_mask.is_some() && cli.shell_cache_mask.is_some()),
        "You may only specify none of all of main_cache_mask, checker_cache_mask, and shell_cache_mask"
    );

    let exit_status = run(
        Command::new(cli.command).args(cli.args),
        RelShellOptions {
            no_cpuid_trap: cli.dont_trap_cpuid,
            no_rdtsc_trap: cli.dont_trap_rdtsc,
            dump_stats: {
                if let Some(path) = cli.stats_output {
                    Some(StatsOutput::File(path))
                } else if cli.dump_stats {
                    Some(StatsOutput::StdOut)
                } else {
                    None
                }
            },
            check_coord_flags: CheckCoordinatorOptions {
                no_state_cmp: cli.no_mem_check,
                no_checker_exec: cli.dont_run_checker,
                no_fork: cli.dont_fork,
                ignore_miscmp: cli.ignore_check_errors,
                enable_async_events: cli.pmu_segmentation,
            },
            checkpoint_period: cli.checkpoint_period,
            max_nr_live_segments: cli.max_nr_live_segments,
            memory_overhead_watermark: cli.max_memory_overhead,
            main_cpu_set: cli.main_cpu_set,
            checker_cpu_set: cli.checker_cpu_set,
            shell_cpu_set: cli.shell_cpu_set,
            main_cpu_freq_governor: cli.main_cpu_freq_governor,
            checker_cpu_freq_governor: cli.checker_cpu_freq_governor,
            shell_cpu_freq_governor: cli.shell_cpu_freq_governor,
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
            dirty_page_tracker: cli.dirty_page_tracker,
            dont_clear_soft_dirty: cli.dont_clear_soft_dirty,
            enable_odf: cli.odf,
            pmu_segmentation_branch_type: cli.pmu_segmentation_branch_type,
            sample_memory_usage: cli.sample_memory_usage,
            memory_sample_includes_rt: cli.memory_sample_includes_rt,
            memory_sample_interval: cli.memory_sample_interval,
            enable_speculative_store_bypass_misfeature: cli
                .enable_speculative_store_bypass_misfeature,
            enable_indirect_branch_speculation_misfeature: cli
                .enable_indirect_branch_speculation_misfeature,
            #[cfg(target_arch = "x86_64")]
            enable_intel_hybrid_workaround: cli.enable_intel_hybrid_workaround,

            slicer: cli.slicer,
            fixed_interval_slicer_skip: cli.fixed_interval_slicer_skip,
            fixed_interval_slicer_reference_type: cli.fixed_interval_slicer_reference_type,

            is_test: false,
            extra_modules: Vec::new(),
        },
    );

    std::process::exit(exit_status.exit_code());
}
