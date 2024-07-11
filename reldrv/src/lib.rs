#![feature(error_generic_member_access)]

pub mod check_coord;
pub mod comparators;
pub mod debug_utils;
pub mod dirty_page_trackers;
pub mod dispatcher;
pub mod error;
pub mod events;
pub mod exec_point_providers;
pub mod helpers;
pub mod inferior_rtlib;
pub mod process;
pub mod signal_handlers;
pub mod slicers;
pub mod statistics;
pub mod syscall_handlers;
pub mod throttlers;
pub mod types;

use std::ffi::OsString;
use std::fmt::Debug;
use std::fs;
use std::ops::Deref;
use std::path::PathBuf;
use std::time::Duration;

use debug_utils::core_dumper::CoreDumper;
use debug_utils::exec_point_dumper::ExecutionPointDumper;
use debug_utils::in_protection_asserter::InProtectionAsserter;
use derivative::Derivative;
use derive_builder::Builder;
use dispatcher::Module;
// use inferior_rtlib::pmu::BranchCounterType;

use helpers::cpufreq::dynamic::DynamicCpuFreqScaler;
use helpers::cpufreq::fixed::FixedCpuFreqGovernorSetter;
use helpers::cpufreq::CpuFreqScalerType;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getpid, Pid};

use log::info;
use signal_handlers::begin_protection::BeginProtectionHandler;
use signal_handlers::slice_segment::SliceSegmentHandler;
use slicers::dynamic::DynamicSlicer;
use slicers::entire_program::EntireProgramSlicer;
use slicers::fixed_interval::FixedIntervalSlicer;
use slicers::{ReferenceType, SlicerType};
use statistics::perf::CounterKind;

use clap::ValueEnum;
use types::exit_reason::ExitReason;
use types::perf_counter::BranchCounterType;

use crate::check_coord::{CheckCoordinator, CheckCoordinatorOptions};
use crate::comparators::intel_hybrid_workaround::IntelHybridWorkaround;
use crate::dirty_page_trackers::fpt::FptDirtyPageTracker;
use crate::dirty_page_trackers::soft_dirty::SoftDirtyPageTracker;
use crate::dispatcher::Dispatcher;

use crate::helpers::affinity::AffinitySetter;
use crate::helpers::checkpoint_size_limiter::CheckpointSizeLimiter;
use crate::helpers::spec_ctrl::SpecCtrlSetter;
use crate::helpers::vdso::VdsoRemover;
// use crate::inferior_rtlib::pmu::PmuSegmentor;

use crate::process::OwnedProcess;
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

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum DirtyPageAddressTrackerType {
    #[default]
    SoftDirty,
    Fpt,
}

#[derive(Debug, Clone)]
pub enum StatsOutput {
    File(PathBuf),
    StdOut,
}

#[derive(Default, Builder, Derivative)]
#[derivative(Debug)]
#[builder(default, pattern = "owned")]
pub struct RelShellOptions {
    /// Dump statistics
    pub dump_stats: Option<StatsOutput>,

    /// Don't trap RDTSC instructions on x86_64
    #[cfg(target_arch = "x86_64")]
    pub no_rdtsc_trap: bool,

    /// Don't trap CPUID instructions on x86_64
    #[cfg(target_arch = "x86_64")]
    pub no_cpuid_trap: bool,

    /// Check coordinator flags
    pub check_coord_flags: CheckCoordinatorOptions,

    /// Checkpoint period
    pub checkpoint_period: u64,

    // nr segments based throttler plugin options
    pub max_nr_live_segments: usize,

    // memory-based throttler plugin options
    pub memory_overhead_watermark: usize,

    // affinity setter plugin options
    pub main_cpu_set: Vec<usize>,
    pub checker_cpu_set: Vec<usize>,
    pub shell_cpu_set: Vec<usize>,
    #[cfg(feature = "intel_cat")]
    pub cache_masks: Option<(u32, u32, u32)>,

    // cpufreq setter plugin options
    pub cpu_freq_scaler_type: CpuFreqScalerType,

    // checkpoint size limiter plugin options
    pub checkpoint_size_watermark: usize,

    // perf counter plugin options
    pub enabled_perf_counters: Vec<CounterKind>,

    // enable automatic segmentation based on precise PMU interrupts
    pub pmu_segmentation: bool, // TODO: change this name
    pub pmu_segmentation_branch_type: BranchCounterType,

    // dirty page tracker backend to use
    pub dirty_page_tracker: DirtyPageAddressTrackerType,

    // soft dirty page tracker options
    pub dont_clear_soft_dirty: bool,

    // odf enabler options
    pub enable_odf: bool,

    // memory sampler options
    pub sample_memory_usage: bool,
    pub memory_sample_includes_rt: bool,
    pub memory_sample_interval: Duration,

    // speculation control options
    pub enable_speculative_store_bypass_misfeature: bool,
    pub enable_indirect_branch_speculation_misfeature: bool,

    #[cfg(target_arch = "x86_64")]
    // Intel hybrid workaround
    pub enable_intel_hybrid_workaround: bool,

    // slicer
    pub slicer: SlicerType,
    pub fixed_interval_slicer_skip: Option<u64>,
    pub fixed_interval_slicer_reference_type: ReferenceType,

    // debug utils
    pub core_dump: bool,
    pub core_dump_dir: PathBuf,

    // integration test
    pub is_test: bool,

    // extra modules
    #[derivative(Debug = "ignore")]
    pub extra_modules: Vec<Box<dyn Module + Sync>>,
}

impl RelShellOptionsBuilder {
    pub fn test_serial_default() -> Self {
        let mut options = Self::default().max_nr_live_segments(1).is_test(true);

        #[cfg(target_arch = "x86_64")]
        {
            options = options.no_cpuid_trap(true).no_rdtsc_trap(true);
        }

        options
    }

    pub fn test_parallel_default() -> Self {
        Self::test_serial_default()
            .max_nr_live_segments(8)
            .is_test(true)
    }
}

pub fn parent_work(child_pid: Pid, options: RelShellOptions) -> ExitReason {
    info!(
        "Starting with args {:?}",
        std::env::args_os().collect::<Vec<OsString>>()
    );

    let child = OwnedProcess::new(child_pid);
    let mut cpuid_overrides = Vec::from(cpuid::overrides::NO_RDRAND);

    assert_eq!(
        waitpid(child.pid, Some(WaitPidFlag::WSTOPPED)).unwrap(),
        WaitStatus::Stopped(child_pid, Signal::SIGSTOP)
    );

    child.seize().expect("Failed to seize process with ptrace");

    let disp = Dispatcher::new();

    // Extras
    for module in options.extra_modules {
        disp.register_module_boxed(module);
    }

    // Non-deterministic instruction handlers
    #[cfg(target_arch = "x86_64")]
    if !options.no_rdtsc_trap {
        disp.register_module(RdtscHandler::new());
    }

    let mut cpuid_handler = None;

    #[cfg(target_arch = "x86_64")]
    if !options.no_cpuid_trap {
        cpuid_handler = Some(disp.register_module(CpuidHandler::new()));
    }

    // Execution point providers
    if options.pmu_segmentation {
        let segmentor = disp.register_module(PerfCounterBasedExecutionPointProvider::new(
            &options.main_cpu_set,
            &options.checker_cpu_set,
            options.pmu_segmentation_branch_type,
            options.is_test,
        ));

        cpuid_overrides.extend(segmentor.get_cpuid_overrides());
    }

    if let Some(handler) = cpuid_handler {
        handler.set_overrides(cpuid_overrides)
    }

    // Syscall handlers
    disp.register_module(RseqHandler::new());
    disp.register_module(CloneHandler::new());
    disp.register_module(ExecveHandler::new());
    disp.register_module(ExitHandler::new());
    disp.register_module(MmapHandler::new());
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
            ));
        }
        SlicerType::EntireProgram => {
            disp.register_module(EntireProgramSlicer::new());
        }
        SlicerType::Dynamic => {
            disp.register_module(DynamicSlicer::new(&options.main_cpu_set));
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
                &options.main_cpu_set,
                &options.checker_cpu_set,
            ));
        }
    }

    disp.register_module(CheckpointSizeLimiter::new(
        options.checkpoint_size_watermark,
    ));

    disp.register_module(SpecCtrlSetter::new(
        options.enable_speculative_store_bypass_misfeature,
        options.enable_indirect_branch_speculation_misfeature,
    ));

    disp.register_module(SliceSegmentHandler);
    disp.register_module(BeginProtectionHandler);

    // Statistics
    let tracer = disp.register_module(Tracer::new());
    disp.register_module(CounterCollector::new());
    disp.register_module(PerfStatsCollector::new(options.enabled_perf_counters));
    disp.register_module(DirtyPageStatsCollector::new());

    if options.sample_memory_usage {
        disp.register_module(MemoryCollector::new(
            options.memory_sample_interval,
            options.memory_sample_includes_rt,
        ));
    }

    // Throttlers
    disp.register_module(MemoryBasedThrottler::new(options.memory_overhead_watermark));
    disp.register_module(NrSegmentsBasedThrottler::new(options.max_nr_live_segments));
    disp.register_module(CheckpointSyncThrottler::new());

    // Dirty page trackers
    match options.dirty_page_tracker {
        DirtyPageAddressTrackerType::SoftDirty => {
            disp.register_module(SoftDirtyPageTracker::new(options.dont_clear_soft_dirty));
        }
        DirtyPageAddressTrackerType::Fpt => {
            disp.register_module(FptDirtyPageTracker::new());
        }
    }

    // Misc
    #[cfg(target_arch = "x86_64")]
    if options.enable_intel_hybrid_workaround {
        disp.register_module(IntelHybridWorkaround::new());
    }

    disp.register_module(ExecutionPointDumper);
    disp.register_module(InProtectionAsserter);

    if options.core_dump {
        disp.register_module(CoreDumper::new("gcore".into(), options.core_dump_dir));
    }

    let check_coord = CheckCoordinator::new(
        child.deref().clone(),
        options.check_coord_flags,
        &disp,
        tracer,
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
