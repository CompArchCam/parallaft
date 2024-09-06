pub mod check_coord;
pub mod comparators;
pub mod debug_utils;
pub mod dirty_page_trackers;
pub mod dispatcher;
pub mod error;
pub mod events;
pub mod exec_point_providers;
pub mod features;
pub mod helpers;
pub mod inferior_rtlib;
pub mod process;
pub mod signal_handlers;
pub mod slicers;
pub mod statistics;
pub mod syscall_handlers;
pub mod throttlers;
pub mod types;
pub mod utils;

#[cfg(test)]
mod test_utils;

use std::fmt::Debug;
use std::fs;
use std::os::unix::process::CommandExt;
use std::path::PathBuf;
use std::process::Command;
use std::time::Duration;

use cfg_if::cfg_if;
use comparators::memory::hasher::HashBasedMemoryComparator;
use comparators::memory::simple::SimpleMemoryComparator;
use comparators::memory::MemoryComparatorType;
use debug_utils::core_dumper::CoreDumper;
use debug_utils::exec_point_dumper::ExecutionPointDumper;
use debug_utils::in_protection_asserter::InProtectionAsserter;
use debug_utils::watchpoint::Watchpoint;
use derivative::Derivative;
use derive_builder::Builder;
use dirty_page_trackers::full::AllWritablePageTracker;
use dirty_page_trackers::kpagecount::KPageCountDirtyPageTracker;
use dirty_page_trackers::null::NullDirtyPageTracker;
#[cfg(feature = "dpt_uffd")]
use dirty_page_trackers::uffd::UffdDirtyPageTracker;
use dirty_page_trackers::DirtyPageAddressTrackerType;
use dispatcher::Module;

use helpers::checker_sched::CheckerScheduler;
use helpers::cpufreq::dynamic::DynamicCpuFreqScaler;
use helpers::cpufreq::fixed::FixedCpuFreqGovernorSetter;
use helpers::cpufreq::CpuFreqScalerType;
use helpers::insn_patcher::InstructionPatcher;
use helpers::madviser::Madviser;
use nix::sys::signal::{raise, Signal};
use nix::sys::wait::{WaitPidFlag, WaitStatus};
use nix::unistd::{fork, getpid, ForkResult, Pid};

use log::info;
use process::state::{Running, WithProcess};
use process::Process;
use serde::{Deserialize, Serialize};
use signal_handlers::begin_protection::BeginProtectionHandler;
use signal_handlers::mrs::MrsHandler;
use signal_handlers::slice_segment::SliceSegmentHandler;
use slicers::dynamic::DynamicSlicer;
use slicers::entire_program::EntireProgramSlicer;
use slicers::fixed_interval::FixedIntervalSlicer;
use slicers::{ReferenceType, SlicerType};
use statistics::hwmon::{HwmonCollector, HwmonSensorPath};
use statistics::perf::CounterKind;
use syscalls::{syscall, Sysno};
use types::exit_reason::ExitReason;
use types::perf_counter::symbolic_events::BranchType;

use crate::check_coord::{CheckCoordinator, CheckCoordinatorOptions};
#[cfg(target_arch = "x86_64")]
use crate::comparators::intel_hybrid_workaround::IntelHybridWorkaround;
#[cfg(feature = "dpt_fpt")]
use crate::dirty_page_trackers::fpt::FptDirtyPageTracker;
use crate::dirty_page_trackers::soft_dirty::SoftDirtyPageTracker;
use crate::dispatcher::Dispatcher;

use crate::helpers::affinity::AffinitySetter;
#[cfg(feature = "helper_checkpoint_size_limiter")]
use crate::helpers::checkpoint_size_limiter::CheckpointSizeLimiter;
#[cfg(target_arch = "x86_64")]
use crate::helpers::spec_ctrl::SpecCtrlSetter;
use crate::helpers::vdso::VdsoRemover;
// use crate::inferior_rtlib::pmu::PmuSegmentor;

#[cfg(target_arch = "x86_64")]
use crate::signal_handlers::cpuid;
use crate::statistics::counter::CounterCollector;
use crate::statistics::dirty_pages::DirtyPageStatsCollector;
use crate::statistics::memory::MemoryCollector;
use crate::statistics::perf::PerfStatsCollector;
use crate::statistics::timing::Tracer;
use crate::statistics::StatisticsProvider;

use crate::syscall_handlers::clone::CloneHandler;
use crate::syscall_handlers::execve::ExecveHandler;
use crate::syscall_handlers::exit::ExitHandler;
use crate::syscall_handlers::mmap::MmapHandler;
use crate::syscall_handlers::record_replay::RecordReplaySyscallHandler;
use crate::syscall_handlers::replicate::ReplicatedSyscallHandler;
use crate::syscall_handlers::rseq::RseqHandler;

use crate::throttlers::checkpoint_sync::CheckpointSyncThrottler;
use crate::throttlers::memory::MemoryBasedThrottler;
use crate::throttlers::nr_segments::NrSegmentsBasedThrottler;

use crate::exec_point_providers::pmu::PerfCounterBasedExecutionPointProvider;

#[cfg(target_arch = "x86_64")]
use crate::signal_handlers::{cpuid::CpuidHandler, rdtsc::RdtscHandler};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub enum StatsOutput {
    File(PathBuf),
    StdOut,
}

#[derive(Builder, Derivative, Serialize, Deserialize)]
#[derivative(Debug, Default)]
#[builder(default, pattern = "owned")]
#[serde(default)]
pub struct RelShellOptions {
    /// Dump statistics
    pub dump_stats: Option<StatsOutput>,

    /// Don't trap RDTSC instructions on x86_64
    #[cfg(target_arch = "x86_64")]
    pub no_rdtsc_trap: bool,

    /// Don't trap CPUID instructions on x86_64
    #[cfg(target_arch = "x86_64")]
    pub no_cpuid_trap: bool,

    /// Don't trap MRS instructions on AArch64
    #[cfg(target_arch = "aarch64")]
    pub no_mrs_trap: bool,

    /// Check coordinator flags
    pub check_coord_flags: CheckCoordinatorOptions,

    /// Checkpoint period
    #[derivative(Default(value = "1000000000"))]
    pub checkpoint_period: u64,

    // nr segments based throttler plugin options
    #[derivative(Default(value = "16"))]
    pub max_nr_live_segments: usize,

    // memory-based throttler plugin options
    pub memory_overhead_watermark: usize,

    // affinity setter plugin options
    pub main_cpu_set: Vec<usize>,
    pub checker_cpu_set: Vec<usize>,
    pub checker_emerg_cpu_set: Vec<usize>,
    pub checker_booster_cpu_set: Vec<usize>,
    pub shell_cpu_set: Vec<usize>,
    #[cfg(feature = "intel_cat")]
    pub cache_masks: Option<(u32, u32, u32)>,

    // cpufreq setter plugin options
    pub cpu_freq_scaler_type: CpuFreqScalerType,
    pub dynamic_cpu_freq_scaler_no_freq_change: bool,

    // checkpoint size limiter plugin options
    pub checkpoint_size_watermark: usize,

    // perf counter plugin options
    pub enabled_perf_counters: Vec<CounterKind>,

    // enable execution point replay support
    pub exec_point_replay: bool,
    pub exec_point_replay_branch_type: BranchType,
    pub exec_point_replay_checker_never_use_branch_count_overflow: bool,

    // dirty page tracker backend to use
    pub dirty_page_tracker: DirtyPageAddressTrackerType,
    pub dont_use_pagemap_scan: bool,

    // soft dirty page tracker options
    pub dont_clear_soft_dirty: bool,

    // odf enabler options
    pub enable_odf: bool,

    // memory sampler options
    pub sample_memory_usage: bool,
    pub memory_sample_includes_rt: bool,
    #[derivative(Default(value = "Duration::from_millis(500)"))]
    pub memory_sample_interval: Duration,

    // hwmon sampler options
    #[derivative(Default(value = "Duration::from_secs(1)"))]
    pub hwmon_sample_interval: Duration,
    pub hwmon_sensor_paths: Vec<HwmonSensorPath>,

    // speculation control options
    pub enable_speculative_store_bypass_misfeature: bool,
    pub enable_indirect_branch_speculation_misfeature: bool,

    // madviser
    pub enable_madviser: bool,

    #[cfg(target_arch = "x86_64")]
    // Intel hybrid workaround
    pub enable_intel_hybrid_workaround: bool,

    // slicer
    pub slicer: SlicerType,
    pub slicer_dont_auto_start: bool,

    // fixed interval slicer
    pub fixed_interval_slicer_skip: Option<u64>,
    pub fixed_interval_slicer_reference_type: ReferenceType,

    // debug utils
    pub core_dump: bool,
    pub core_dump_dir: PathBuf,
    pub watchpoint_addresses: Vec<usize>,

    // memory comparator options
    pub memory_comparator: MemoryComparatorType,

    // integration test
    #[serde(skip)]
    pub is_test: bool,

    // extra modules
    #[serde(skip)]
    #[derivative(Debug = "ignore")]
    pub extra_modules: Vec<Box<dyn Module + Sync>>,
}

impl RelShellOptionsBuilder {
    pub fn test_serial_default() -> Self {
        let mut options = Self::default().max_nr_live_segments(1).is_test(true);

        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                options = options.no_cpuid_trap(true).no_rdtsc_trap(true);
            }
            else {
                let _ = &mut options;
            }
        }

        options
    }

    pub fn test_parallel_default() -> Self {
        Self::test_serial_default()
            .max_nr_live_segments(8)
            .is_test(true)
    }
}

pub fn parent_work(
    child_pid: Pid,
    mut options: RelShellOptions,
) -> crate::error::Result<ExitReason> {
    info!("Starting with options {:#?}", &options);

    #[cfg(target_arch = "x86_64")]
    let mut cpuid_overrides = Vec::from(cpuid::overrides::NO_RDRAND);

    let WithProcess(child, status) = Process::new(child_pid, Running)
        .waitpid_with_flags(Some(WaitPidFlag::WSTOPPED))
        .unwrap()
        .unwrap_stopped();

    assert_eq!(status, WaitStatus::Stopped(child_pid, Signal::SIGSTOP));

    let child = child.seize().expect("Failed to seize process");

    let disp = Dispatcher::new();

    // Extras
    for module in options.extra_modules {
        disp.register_module_boxed(module);
    }

    // Non-deterministic instruction handlers

    let mut insn_patcher = InstructionPatcher::new();

    cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            if !options.no_rdtsc_trap {
                disp.register_module(RdtscHandler::new());
            }

            let mut cpuid_handler = None;

            if !options.no_cpuid_trap {
                cpuid_handler = Some(disp.register_module(CpuidHandler::new()));
            }
        }
        else if #[cfg(target_arch = "aarch64")] {
            if !options.no_mrs_trap {
                disp.register_module(MrsHandler::new(&mut insn_patcher));
            }
        }
    }

    disp.register_module(insn_patcher);

    // Execution point providers
    if options.exec_point_replay {
        options.check_coord_flags.enable_async_events = true;

        let exec_point_provider =
            disp.register_module(PerfCounterBasedExecutionPointProvider::new(
                &options.main_cpu_set,
                options.exec_point_replay_branch_type,
                options.exec_point_replay_checker_never_use_branch_count_overflow,
            ));

        cfg_if::cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                cpuid_overrides.extend(exec_point_provider.get_cpuid_overrides());
            }
            else {
                let _ = &exec_point_provider;
            }
        }
    }

    #[cfg(target_arch = "x86_64")]
    if let Some(handler) = cpuid_handler {
        handler.set_overrides(cpuid_overrides)
    }

    // Syscall handlers
    disp.register_module(RseqHandler::new());
    disp.register_module(CloneHandler::new());
    disp.register_module(ExecveHandler::new());
    disp.register_module(ExitHandler::new());
    disp.register_module(MmapHandler::new(options.is_test));
    disp.register_module(ReplicatedSyscallHandler::new());
    disp.register_module(RecordReplaySyscallHandler::new());

    // Slicer
    match options.slicer {
        SlicerType::FixedInterval => {
            disp.register_module(FixedIntervalSlicer::new(
                options.fixed_interval_slicer_skip,
                options.checkpoint_period,
                options.fixed_interval_slicer_reference_type,
                &options.main_cpu_set,
                options.is_test,
                !options.slicer_dont_auto_start,
            ));
        }
        SlicerType::EntireProgram => {
            disp.register_module(EntireProgramSlicer::new());
        }
        SlicerType::Dynamic => {
            disp.register_module(DynamicSlicer::new(options.max_nr_live_segments));
        }
        SlicerType::Null => (),
    };

    // Misc
    disp.register_module(VdsoRemover::new());

    #[cfg(not(feature = "intel_cat"))]
    disp.register_module(AffinitySetter::new(
        &options.main_cpu_set,
        &options.checker_cpu_set,
    ));

    #[cfg(feature = "intel_cat")]
    disp.register_module(AffinitySetter::new_with_cache_allocation(
        &options.main_cpu_set,
        &options.checker_cpu_set,
        &options.shell_cpu_set,
        options.cache_masks,
    ));

    match options.cpu_freq_scaler_type {
        CpuFreqScalerType::Null => (),
        CpuFreqScalerType::Fixed(governor) => {
            disp.register_module(FixedCpuFreqGovernorSetter::new(
                &options.checker_cpu_set,
                governor,
            ));
        }
        CpuFreqScalerType::Dynamic => {
            disp.register_module(DynamicCpuFreqScaler::new(
                &options.checker_cpu_set,
                &options.checker_emerg_cpu_set,
                options.dynamic_cpu_freq_scaler_no_freq_change,
            ));
        }
    }

    #[cfg(feature = "helper_checkpoint_size_limiter")]
    disp.register_module(CheckpointSizeLimiter::new(
        options.checkpoint_size_watermark,
    ));

    #[cfg(target_arch = "x86_64")]
    disp.register_module(SpecCtrlSetter::new(
        options.enable_speculative_store_bypass_misfeature,
        options.enable_indirect_branch_speculation_misfeature,
    ));

    disp.register_module(SliceSegmentHandler);
    disp.register_module(BeginProtectionHandler);

    if options.enable_madviser {
        disp.register_module(Madviser::new());
    }

    if options.checker_cpu_set.len() > 0 {
        disp.register_module(CheckerScheduler::new(
            &options.checker_cpu_set,
            &options.checker_emerg_cpu_set,
            &options.checker_booster_cpu_set,
            true,
            true,
        ));
    }

    // Statistics
    let tracer = disp.register_module(Tracer::new());
    disp.register_module(CounterCollector::new());
    disp.register_module(PerfStatsCollector::new(options.enabled_perf_counters));
    disp.register_module(DirtyPageStatsCollector::new());

    if !options.hwmon_sensor_paths.is_empty() {
        disp.register_module(HwmonCollector::new(
            options.hwmon_sample_interval,
            options.hwmon_sensor_paths,
        ));
    }

    if options.sample_memory_usage {
        disp.register_module(MemoryCollector::new(
            options.memory_sample_interval,
            options.memory_sample_includes_rt,
            true,
        ));
    }

    // Throttlers
    disp.register_module(MemoryBasedThrottler::new(options.memory_overhead_watermark));
    disp.register_module(NrSegmentsBasedThrottler::new(options.max_nr_live_segments));
    disp.register_module(CheckpointSyncThrottler::new());

    // Dirty page trackers
    match options.dirty_page_tracker {
        DirtyPageAddressTrackerType::SoftDirty
        | DirtyPageAddressTrackerType::PagemapScanSoftDirty => {
            disp.register_module(SoftDirtyPageTracker::new(
                options.dont_clear_soft_dirty,
                options.dirty_page_tracker == DirtyPageAddressTrackerType::SoftDirty,
            ));
        }
        #[cfg(feature = "dpt_fpt")]
        DirtyPageAddressTrackerType::Fpt => {
            disp.register_module(FptDirtyPageTracker::new());
        }
        #[cfg(feature = "dpt_uffd")]
        DirtyPageAddressTrackerType::Uffd => {
            disp.register_module(UffdDirtyPageTracker::new(options.dont_clear_soft_dirty));
        }
        DirtyPageAddressTrackerType::KPageCount
        | DirtyPageAddressTrackerType::PagemapScanUnique => {
            disp.register_module(KPageCountDirtyPageTracker::new(
                options.dirty_page_tracker == DirtyPageAddressTrackerType::KPageCount,
            ));
        }
        DirtyPageAddressTrackerType::Full => {
            disp.register_module(AllWritablePageTracker::new());
        }
        DirtyPageAddressTrackerType::None => {
            disp.register_module(NullDirtyPageTracker::new());
        }
    }

    // Misc
    #[cfg(target_arch = "x86_64")]
    if options.enable_intel_hybrid_workaround {
        disp.register_module(IntelHybridWorkaround::new());
    }

    match options.memory_comparator {
        MemoryComparatorType::Hasher => {
            disp.register_module(HashBasedMemoryComparator::new());
        }
        MemoryComparatorType::Simple => {
            disp.register_module(SimpleMemoryComparator::new());
        }
        MemoryComparatorType::None => (),
    }

    disp.register_module(ExecutionPointDumper);
    disp.register_module(InProtectionAsserter);
    disp.register_module(Watchpoint::new(&options.watchpoint_addresses));

    if options.core_dump {
        disp.register_module(CoreDumper::new("gcore".into(), options.core_dump_dir));
    }

    let check_coord = CheckCoordinator::new(
        child.unowned_copy(),
        options.check_coord_flags,
        &disp,
        tracer,
        options.checker_cpu_set.clone(),
    );

    info!("Shell PID: {}", getpid());

    let all_wall_time_tracer = tracer.trace(statistics::timing::Event::AllWall);

    let exit_status = std::thread::scope(|scope| check_coord.main_work(child, scope));

    info!("Exit reason: {exit_status:?}");

    all_wall_time_tracer.end();

    if let Some(ref output) = options.dump_stats {
        let s = statistics::as_text(&disp.statistics());

        match output {
            StatsOutput::File(path) => fs::write(path, s).unwrap(),
            StatsOutput::StdOut => println!("{}", s),
        }
    }

    exit_status
}

pub fn run(cmd: &mut Command, options: RelShellOptions) -> crate::error::Result<ExitReason> {
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
