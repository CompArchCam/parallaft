pub mod check_coord;
pub mod dirty_page_trackers;
pub mod dispatcher;
pub mod error;
pub mod helpers;
pub mod inferior_rtlib;
pub mod process;
pub mod saved_syscall;
pub mod segments;
pub mod signal_handlers;
pub mod statistics;
pub mod syscall_handlers;
pub mod throttlers;
pub mod utils;

use std::ffi::OsString;

use std::fs;
use std::ops::Deref;
use std::panic::{catch_unwind, AssertUnwindSafe};
use std::path::PathBuf;
use std::time::Duration;

use derive_builder::Builder;
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::{getpid, Pid};

use log::info;
use scopeguard::defer;
use statistics::perf::CounterKind;

use clap::ValueEnum;

use crate::check_coord::{CheckCoordinator, CheckCoordinatorOptions};
use crate::check_coord::{ExitReason, ProcessIdentity};
use crate::dirty_page_trackers::fpt::FptDirtyPageTracker;
use crate::dirty_page_trackers::soft_dirty::SoftDirtyPageTracker;
use crate::dispatcher::{Dispatcher, Halt};

use crate::helpers::affinity::AffinitySetter;
use crate::helpers::checkpoint_size_limiter::CheckpointSizeLimiter;
use crate::helpers::cpufreq::CpuFreqGovernor;
use crate::helpers::cpufreq::CpuFreqSetter;
use crate::helpers::vdso::VdsoRemover;
use crate::inferior_rtlib::legacy::LegacyInferiorRtLib;
use crate::inferior_rtlib::pmu::PmuSegmentor;
use crate::inferior_rtlib::relrtlib::RelRtLib;

use crate::process::OwnedProcess;
use crate::statistics::counter::CounterCollector;
use crate::statistics::dirty_pages::DirtyPageStatsCollector;
use crate::statistics::memory::MemoryCollector;
use crate::statistics::perf::PerfStatsCollector;
use crate::statistics::timing::TimingCollector;

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

#[derive(Debug, Default, Builder)]
#[builder(default)]
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
    pub main_cpu_freq_governor: Option<CpuFreqGovernor>,
    pub checker_cpu_freq_governor: Option<CpuFreqGovernor>,
    pub shell_cpu_freq_governor: Option<CpuFreqGovernor>,

    // checkpoint size limiter plugin options
    pub checkpoint_size_watermark: usize,

    // perf counter plugin options
    pub enabled_perf_counters: Vec<CounterKind>,

    // enable automatic segmentation based on precise PMU interrupts
    pub pmu_segmentation: bool,
    pub pmu_segmentation_skip_instructions: Option<u64>,

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

    // integration test
    pub is_test: bool,
}

impl RelShellOptionsBuilder {
    pub fn test_serial_default() -> Self {
        let mut options = Self::default();

        #[cfg(target_arch = "x86_64")]
        options.no_cpuid_trap(true).no_rdtsc_trap(true);

        options.max_nr_live_segments(1).is_test(true);

        options
    }

    pub fn test_parallel_default() -> Self {
        let mut options = Self::test_serial_default();

        options.max_nr_live_segments(8).is_test(true);

        options
    }
}

pub fn parent_work(child_pid: Pid, options: RelShellOptions) -> ExitReason {
    info!(
        "Starting with args {:?}",
        std::env::args_os().collect::<Vec<OsString>>()
    );

    let child = OwnedProcess::new(child_pid);

    assert_eq!(
        waitpid(child.pid, Some(WaitPidFlag::WSTOPPED)).unwrap(),
        WaitStatus::Stopped(child_pid, Signal::SIGSTOP)
    );

    child.seize().expect("Failed to seize process with ptrace");

    let disp = Dispatcher::new();

    // Syscall handlers
    disp.register_module(RseqHandler::new());
    disp.register_module(CloneHandler::new());
    disp.register_module(ExecveHandler::new());
    disp.register_module(ExitHandler::new());
    disp.register_module(MmapHandler::new());
    disp.register_module(ReplicatedSyscallHandler::new());
    disp.register_module(RecordReplaySyscallHandler::new());

    // Non-deterministic instruction handlers
    #[cfg(target_arch = "x86_64")]
    if !options.no_rdtsc_trap {
        disp.register_module(RdtscHandler::new());
    }

    #[cfg(target_arch = "x86_64")]
    if !options.no_cpuid_trap {
        disp.register_module(CpuidHandler::new());
    }

    // Segmentation
    if options.pmu_segmentation {
        disp.register_module(PmuSegmentor::new(
            options.checkpoint_period,
            options.pmu_segmentation_skip_instructions,
            &options.main_cpu_set,
            &options.checker_cpu_set,
            options.is_test,
        ));
    } else {
        disp.register_module(LegacyInferiorRtLib::new());
        disp.register_module(RelRtLib::new(options.checkpoint_period));
    }

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

    disp.register_module(CpuFreqSetter::new(
        &options.main_cpu_set,
        &options.checker_cpu_set,
        &options.shell_cpu_set,
        options.main_cpu_freq_governor,
        options.checker_cpu_freq_governor,
        options.shell_cpu_freq_governor,
    ));

    disp.register_module(CheckpointSizeLimiter::new(
        options.checkpoint_size_watermark,
    ));

    // Statistics
    disp.register_module(TimingCollector::new());
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

    let mut exit_status = ExitReason::Panic;

    let check_coord =
        CheckCoordinator::new(child.deref().clone(), options.check_coord_flags, &disp);

    info!("Shell PID = {}", getpid());

    std::thread::scope(|scope| {
        defer!(disp.halt());

        let status = catch_unwind(AssertUnwindSafe(|| {
            exit_status = check_coord
                .run_event_loop(ProcessIdentity::Main(child.deref()), scope)
                .unwrap();

            check_coord.wait_until_and_handle_completion(scope).unwrap();

            if check_coord.has_errors() {
                exit_status = ExitReason::StateMismatch
            }
        }));

        if status.is_err() {
            check_coord.handle_panic();
        }

        if let Some(ref output) = options.dump_stats {
            let s = format!("{}\n", statistics::as_text(disp.statistics()));

            match output {
                StatsOutput::File(path) => fs::write(path, s).unwrap(),
                StatsOutput::StdOut => print!("{}", s),
            }
        }
    });

    exit_status
}
