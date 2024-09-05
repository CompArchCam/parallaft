use std::fs::OpenOptions;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use clap::{Parser, ValueEnum};
use clap_num::maybe_hex;
use git_version::git_version;

use reldrv::comparators::memory::MemoryComparatorType;
use reldrv::dirty_page_trackers::DirtyPageAddressTrackerType;
use reldrv::helpers::cpufreq::{CpuFreqGovernor, CpuFreqScalerType};
use reldrv::slicers::{ReferenceType, SlicerType};
use reldrv::statistics::hwmon::HwmonSensorPath;
use reldrv::types::perf_counter::symbolic_events::BranchType;
use reldrv::StatsOutput;
use reldrv::{statistics::perf::CounterKind, RelShellOptions};

#[derive(Debug, Clone, Copy, ValueEnum, Default)]
enum CpuFreqScalerTypeCli {
    #[default]
    Null,
    Fixed,
    Dynamic,
}

#[derive(Parser, Debug)]
#[command(version = git_version!())]
struct CliArgs {
    /// Config file to use
    #[arg(short, long)]
    config: Option<PathBuf>,

    /// Main CPU set
    #[arg(short, long, use_value_delimiter = true)]
    main_cpu_set: Option<Vec<usize>>,

    /// Checker CPU set
    #[arg(short = 'C', long, use_value_delimiter = true)]
    checker_cpu_set: Option<Vec<usize>>,

    /// Emergency CPU set used by checkers if checkers cannot keep up
    #[arg(long, use_value_delimiter = true)]
    checker_emerg_cpu_set: Option<Vec<usize>>,

    /// Booster CPU set used by checkers (usually the big cores) after the main finishes
    #[arg(long, use_value_delimiter = true)]
    checker_booster_cpu_set: Option<Vec<usize>>,

    /// Shell CPU set
    #[arg(short, long, use_value_delimiter = true)]
    shell_cpu_set: Option<Vec<usize>>,

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

    /// CPU frequency scaler to use.
    #[arg(long)]
    cpu_freq_scaler: Option<CpuFreqScalerTypeCli>,

    /// Disallow frequency change (while allowing checkers to be migrated to emergency CPU set, if configured) when dynamic CPU frequency scaler is used.
    #[arg(long)]
    no_freq_change: Option<bool>,

    /// When `cpu_freq_scaler` is set to "fixed", the CPU freqeuncy governor to use. Possible values: userspace:<freq_in_khz>, ondemand, ondemand:<max_freq_in_khz>. Requires `--checker-cpu-set` set.
    #[arg(long)]
    checker_cpu_freq_governor: Option<CpuFreqGovernor>,

    /// Don't compare state between the checker and the reference.
    #[arg(long)]
    no_state_cmp: Option<bool>,

    /// Memory comparator to use.
    #[arg(long)]
    memory_comparator: Option<MemoryComparatorType>,

    /// Don't run the checker process. Just fork, and kill it until the next checkpoint.
    #[arg(long)]
    dont_run_checker: Option<bool>,

    /// Don't clear soft-dirty bits in each iteration. Depends on `--no-mem-check`.
    #[arg(long)]
    dont_clear_soft_dirty: Option<bool>,

    /// Don't fork the main process. Implies `--dont-run-checker`, `--no-mem-check` and `--dont-clear-soft-dirty`.
    #[arg(long)]
    dont_fork: Option<bool>,

    /// Ignore check errors.
    #[arg(long)]
    ignore_check_errors: Option<bool>,

    /// Dump statistics.
    #[arg(long)]
    dump_stats: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    /// Don't trap rdtsc instructions.
    #[arg(long)]
    dont_trap_rdtsc: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    /// Don't trap cpuid instructions.
    #[arg(long)]
    dont_trap_cpuid: Option<bool>,

    #[cfg(target_arch = "aarch64")]
    /// Don't trap mrs instructions.
    #[arg(long)]
    dont_trap_mrs: Option<bool>,

    /// File to dump stats to.
    #[arg(long)]
    stats_output: Option<PathBuf>,

    /// File to write logs to.
    #[arg(long)]
    log_output: Option<PathBuf>,

    /// Maximum number of live segments (0 = unlimited).
    #[arg(long)]
    max_nr_live_segments: Option<usize>,

    /// Memory overhead limit in bytes (0 = unlimited).
    #[arg(long)]
    max_memory_overhead: Option<usize>,

    /// Checkpoint size watermark in number of pages (0 = unlimited).
    #[arg(long)]
    checkpoint_size_watermark: Option<usize>,

    /// Checkpoint period in number of instructions. Used by librelrt and PMU-based segmentor.
    #[arg(short = 'P', long)]
    checkpoint_period: Option<u64>,

    /// Perf counters to sample during the inferior execution.
    #[arg(long, use_value_delimiter = true)]
    enabled_perf_counters: Option<Vec<CounterKind>>,

    /// Enable execution point record and replay support.
    #[arg(short, long)]
    exec_point_replay: Option<bool>,

    /// Reference branch event to use for execution points.
    #[arg(long)]
    exec_point_replay_branch_type: Option<BranchType>,

    /// During replay of an execution point for a checker, always use breakpoints instead of branch count overflow events.
    #[arg(long)]
    exec_point_replay_checker_never_use_branch_count_overflow: Option<bool>,

    /// Dirty page tracker to use
    #[arg(long)]
    dirty_page_tracker: Option<DirtyPageAddressTrackerType>,

    /// Don't use the faster PAGEMAP_SCAN ioctl to get dirty pages. Only
    /// applicable to soft-dirty and k-page-count page tracker.
    #[arg(long)]
    dont_use_pagemap_scan: Option<bool>,

    /// Enable on-demand fork (ODF)
    #[arg(long)]
    odf: Option<bool>,

    /// Sample memory usage
    #[arg(long)]
    sample_memory_usage: Option<bool>,

    /// Include runtime memory usage in memory usage sampling
    #[arg(long)]
    memory_sample_includes_rt: Option<bool>,

    /// Memory sample interval in milliseconds
    #[arg(long, value_parser = parse_duration)]
    memory_sample_interval: Option<Duration>,

    /// Hwmon sample interval in milliseconds
    #[arg(long, value_parser = parse_duration)]
    hwmon_sample_interval: Option<Duration>,

    /// Hwmon power sensor paths to sample (e.g. macsmc_hwmon/CPU P-cores Power)
    #[arg(long, use_value_delimiter = true, value_parser = HwmonSensorPath::parse)]
    hwmon_sensor_paths: Option<Vec<HwmonSensorPath>>,

    /// Enable speculative store bypass misfeature
    #[arg(long)]
    enable_speculative_store_bypass_misfeature: Option<bool>,

    /// Enable indirect branch speculation misfeature
    #[arg(long)]
    enable_indirect_branch_speculation_misfeature: Option<bool>,

    /// Advise the kernel to swap out checkpoint pages should there be a memory pressure
    #[arg(long)]
    madviser: Option<bool>,

    #[cfg(target_arch = "x86_64")]
    /// Enable Intel hybrid CPU workaround
    #[arg(long)]
    enable_intel_hybrid_workaround: Option<bool>,

    /// Strategy to use for automatically slicing the inferior
    #[arg(short = 'S', long)]
    slicer: Option<SlicerType>,

    #[arg(long)]
    fixed_interval_slicer_skip: Option<u64>,

    #[arg(long)]
    fixed_interval_slicer_reference_type: Option<ReferenceType>,

    /// Don't start slicing automatically. Works for fixed-interval slicer only.
    #[arg(long)]
    slicer_dont_auto_start: Option<bool>,

    /// Make a core dump on check failures
    #[arg(long)]
    core_dump: Option<bool>,

    /// Output directory of the core dumps
    #[arg(long)]
    core_dump_dir: Option<PathBuf>,

    /// Addresses to register write watchpoints on
    #[arg(long, value_parser=maybe_hex::<usize>)]
    watchpoint_address: Option<Vec<usize>>,

    command: String,
    args: Vec<String>,
}

fn parse_duration(arg: &str) -> Result<std::time::Duration, std::num::ParseIntError> {
    Ok(std::time::Duration::from_millis(arg.parse()?))
}

fn apply_if_some<T>(
    options: &mut RelShellOptions,
    opt: Option<T>,
    f: impl FnOnce(&mut RelShellOptions, T) -> (),
) {
    if let Some(val) = opt {
        f(options, val);
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

    let mut config: RelShellOptions;
    if let Some(config_filename) = cli.config {
        config = serde_yaml::from_reader(
            std::fs::File::open(config_filename).expect("Can't open config file"),
        )
        .expect("Can't parse config file");
    } else {
        config = RelShellOptions::default();
    }

    #[cfg(target_arch = "x86_64")]
    apply_if_some(&mut config, cli.no_cpuid_trap, |config, val| {
        config.no_cpuid_trap = val;
    });

    #[cfg(target_arch = "x86_64")]
    apply_if_some(&mut config, cli.no_rdtsc_trap, |config, val| {
        config.no_rdtsc_trap = val;
    });

    #[cfg(target_arch = "aarch64")]
    apply_if_some(&mut config, cli.dont_trap_mrs, |config, val| {
        config.no_mrs_trap = val;
    });

    apply_if_some(&mut config, cli.dump_stats, |config, val| {
        if val {
            config.dump_stats = Some(StatsOutput::StdOut);
        }
    });

    apply_if_some(&mut config, cli.stats_output, |config, val| {
        config.dump_stats = Some(StatsOutput::File(val));
    });

    apply_if_some(&mut config, cli.no_state_cmp, |config, val| {
        config.check_coord_flags.no_state_cmp = val;
    });

    apply_if_some(&mut config, cli.dont_run_checker, |config, val| {
        config.check_coord_flags.no_checker_exec = val;
    });

    apply_if_some(&mut config, cli.dont_fork, |config, val| {
        config.check_coord_flags.no_fork = val;
    });

    apply_if_some(&mut config, cli.ignore_check_errors, |config, val| {
        config.check_coord_flags.ignore_miscmp = val;
    });

    apply_if_some(&mut config, cli.exec_point_replay, |config, val| {
        config.exec_point_replay = val;
    });

    // checkpoint_period
    apply_if_some(&mut config, cli.checkpoint_period, |config, val| {
        config.checkpoint_period = val;
    });

    // max_nr_live_segments
    apply_if_some(&mut config, cli.max_nr_live_segments, |config, val| {
        config.max_nr_live_segments = val;
    });

    // max_memory_overhead
    apply_if_some(&mut config, cli.max_memory_overhead, |config, val| {
        config.memory_overhead_watermark = val;
    });

    // main_cpu_set
    apply_if_some(&mut config, cli.main_cpu_set, |config, val| {
        config.main_cpu_set = val;
    });

    // checker_cpu_set
    apply_if_some(&mut config, cli.checker_cpu_set, |config, val| {
        config.checker_cpu_set = val;
    });

    // checker_emerg_cpu_set
    apply_if_some(&mut config, cli.checker_emerg_cpu_set, |config, val| {
        config.checker_emerg_cpu_set = val;
    });

    // checker_booster_cpu_set
    apply_if_some(&mut config, cli.checker_booster_cpu_set, |config, val| {
        config.checker_booster_cpu_set = val;
    });

    // shell_cpu_set
    apply_if_some(&mut config, cli.shell_cpu_set, |config, val| {
        config.shell_cpu_set = val;
    });

    // cpu_freq_scaler
    apply_if_some(&mut config, cli.cpu_freq_scaler, |config, val| match val {
        CpuFreqScalerTypeCli::Null => config.cpu_freq_scaler_type = CpuFreqScalerType::Null,
        CpuFreqScalerTypeCli::Fixed => {
            config.cpu_freq_scaler_type = CpuFreqScalerType::Fixed(cli.checker_cpu_freq_governor.expect("You must set `--checker-cpu-freq-governor` when you use fixed CPU frequency scaler"));
        }
        CpuFreqScalerTypeCli::Dynamic => {
            config.cpu_freq_scaler_type = CpuFreqScalerType::Dynamic;
        }
    });

    // no_freq_change
    apply_if_some(&mut config, cli.no_freq_change, |config, val| {
        config.dynamic_cpu_freq_scaler_no_freq_change = val;
    });

    // checkpoint_size_watermark
    apply_if_some(&mut config, cli.checkpoint_size_watermark, |config, val| {
        config.checkpoint_size_watermark = val;
    });

    // cache_masks
    apply_if_some(&mut config, cli.main_cache_mask, |config, val| {
        apply_if_some(config, cli.checker_cache_mask, |config, val2| {
            apply_if_some(config, cli.shell_cache_mask, |config, val3| {
                config.cache_masks = Some((val, val2, val3));
            });
        });
    });

    // enabled_perf_counters
    apply_if_some(&mut config, cli.enabled_perf_counters, |config, val| {
        config.enabled_perf_counters = val;
    });

    // exec_point_replay_branch_type
    apply_if_some(
        &mut config,
        cli.exec_point_replay_branch_type,
        |config, val| {
            config.exec_point_replay_branch_type = val;
        },
    );

    // exec_point_replay_checker_never_use_branch_count_overflow
    apply_if_some(
        &mut config,
        cli.exec_point_replay_checker_never_use_branch_count_overflow,
        |config, val| {
            config.exec_point_replay_checker_never_use_branch_count_overflow = val;
        },
    );

    // dirty_page_tracker
    apply_if_some(&mut config, cli.dirty_page_tracker, |config, val| {
        config.dirty_page_tracker = val;
    });

    // dont_use_pagemap_scan
    apply_if_some(&mut config, cli.dont_use_pagemap_scan, |config, val| {
        config.dont_use_pagemap_scan = val;
    });

    // dont_clear_soft_dirty
    apply_if_some(&mut config, cli.dont_clear_soft_dirty, |config, val| {
        config.dont_clear_soft_dirty = val;
    });

    // odf
    apply_if_some(&mut config, cli.odf, |config, val| {
        config.enable_odf = val;
    });

    // sample_memory_usage
    apply_if_some(&mut config, cli.sample_memory_usage, |config, val| {
        config.sample_memory_usage = val;
    });

    // memory_sample_includes_rt
    apply_if_some(&mut config, cli.memory_sample_includes_rt, |config, val| {
        config.memory_sample_includes_rt = val;
    });

    // memory_sample_interval
    apply_if_some(&mut config, cli.memory_sample_interval, |config, val| {
        config.memory_sample_interval = val;
    });

    // hwmon_sample_interval
    apply_if_some(&mut config, cli.hwmon_sample_interval, |config, val| {
        config.hwmon_sample_interval = val;
    });

    // hwmon_sensor_paths
    apply_if_some(&mut config, cli.hwmon_sensor_paths, |config, val| {
        config.hwmon_sensor_paths = val;
    });

    // enable_speculative_store_bypass_misfeature
    apply_if_some(
        &mut config,
        cli.enable_speculative_store_bypass_misfeature,
        |config, val| {
            config.enable_speculative_store_bypass_misfeature = val;
        },
    );

    // enable_indirect_branch_speculation_misfeature
    apply_if_some(
        &mut config,
        cli.enable_indirect_branch_speculation_misfeature,
        |config, val| {
            config.enable_indirect_branch_speculation_misfeature = val;
        },
    );

    // enable_madviser
    apply_if_some(&mut config, cli.madviser, |config, val| {
        config.enable_madviser = val;
    });

    #[cfg(target_arch = "x86_64")]
    // enable_intel_hybrid_workaround
    apply_if_some(
        &mut config,
        cli.enable_intel_hybrid_workaround,
        |config, val| {
            config.enable_intel_hybrid_workaround = val;
        },
    );

    // slicer
    apply_if_some(&mut config, cli.slicer, |config, val| {
        config.slicer = val;
    });

    // slicer_dont_auto_start
    apply_if_some(&mut config, cli.slicer_dont_auto_start, |config, val| {
        config.slicer_dont_auto_start = val;
    });

    // fixed_interval_slicer_skip
    apply_if_some(
        &mut config,
        cli.fixed_interval_slicer_skip,
        |config, val| {
            config.fixed_interval_slicer_skip = Some(val);
        },
    );

    // fixed_interval_slicer_reference_type
    apply_if_some(
        &mut config,
        cli.fixed_interval_slicer_reference_type,
        |config, val| {
            config.fixed_interval_slicer_reference_type = val;
        },
    );

    // core_dump
    apply_if_some(&mut config, cli.core_dump, |config, val| {
        config.core_dump = val;
    });

    // core_dump_dir
    apply_if_some(&mut config, cli.core_dump_dir, |config, val| {
        config.core_dump_dir = val;
    });

    // watchpoint_address
    apply_if_some(&mut config, cli.watchpoint_address, |config, val| {
        config.watchpoint_addresses = val;
    });

    // memory_comparator
    apply_if_some(&mut config, cli.memory_comparator, |config, val| {
        config.memory_comparator = val;
    });

    let exit_status = reldrv::run(Command::new(cli.command).args(cli.args), config);

    std::process::exit(exit_status.map_or(255, |x| x.exit_code()));
}
