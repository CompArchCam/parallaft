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

use std::collections::HashMap;
use std::fs;
use std::panic;
use std::panic::catch_unwind;
use std::panic::AssertUnwindSafe;
use std::path::PathBuf;
use std::time::Duration;

use bitflags::bitflags;

use nix::errno::Errno;
use nix::sys::ptrace::{self, SyscallInfoOp};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use log::{info, warn};
use statistics::perf::CounterKind;

use clap::ValueEnum;

use crate::check_coord::{CheckCoordinator, CheckCoordinatorFlags};
use crate::dirty_page_trackers::fpt::FptDirtyPageTracker;
use crate::dirty_page_trackers::soft_dirty::SoftDirtyPageTracker;
use crate::dispatcher::Dispatcher;
use crate::dispatcher::Halt;
use crate::helpers::affinity::AffinitySetter;
use crate::helpers::checkpoint_size_limiter::CheckpointSizeLimiter;
use crate::helpers::cpufreq::CpuFreqGovernor;
use crate::helpers::cpufreq::CpuFreqSetter;
use crate::helpers::vdso::VdsoRemover;
use crate::inferior_rtlib::legacy::LegacyInferiorRtLib;
use crate::inferior_rtlib::pmu::PmuSegmentor;
use crate::inferior_rtlib::relrtlib::RelRtLib;
use crate::process::ProcessLifetimeHook;
use crate::process::ProcessLifetimeHookContext;
use crate::process::{OwnedProcess, Process};
use crate::segments::CheckpointCaller;
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
use crate::syscall_handlers::replicate::ReplicatedSyscallHandler;
use crate::syscall_handlers::rseq::RseqHandler;
use crate::syscall_handlers::{CustomSyscallHandler, HandlerContext, SyscallHandlerExitAction};
use crate::throttlers::memory::MemoryBasedThrottler;
use crate::throttlers::nr_segments::NrSegmentsBasedThrottler;

#[cfg(target_arch = "x86_64")]
use crate::signal_handlers::cpuid::CpuidHandler;

#[cfg(target_arch = "x86_64")]
use crate::signal_handlers::rdtsc::RdtscHandler;

bitflags! {
    #[derive(Default)]
    pub struct RunnerFlags: u32 {
        const POLL_WAITPID = 0b00000001;
        const DUMP_STATS = 0b00000010;
        #[cfg(target_arch = "x86_64")]
        const DONT_TRAP_RDTSC = 0b00000100;
        #[cfg(target_arch = "x86_64")]
        const DONT_TRAP_CPUID = 0b00001000;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum DirtyPageAddressTrackerType {
    #[default]
    SoftDirty,
    Fpt,
}

#[derive(Debug, Default)]
pub struct RelShellOptions {
    pub runner_flags: RunnerFlags,
    pub check_coord_flags: CheckCoordinatorFlags,
    pub stats_output: Option<PathBuf>,
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
}

#[allow(unused)]
impl RelShellOptions {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_max_nr_live_segments(mut self, max_nr_live_segments: usize) -> Self {
        self.max_nr_live_segments = max_nr_live_segments;
        self
    }

    pub fn with_checkpoint_size_watermark(mut self, checkpoint_size_watermark: usize) -> Self {
        self.checkpoint_size_watermark = checkpoint_size_watermark;
        self
    }
}

pub fn parent_work(child_pid: Pid, options: RelShellOptions) -> i32 {
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

    let disp = Dispatcher::new();

    // Syscall handlers
    disp.register_module(RseqHandler::new());
    disp.register_module(CloneHandler::new());
    disp.register_module(ExecveHandler::new());
    disp.register_module(ExitHandler::new());
    disp.register_module(MmapHandler::new());
    disp.register_module(ReplicatedSyscallHandler::new());

    // Non-deterministic instruction handlers
    #[cfg(target_arch = "x86_64")]
    if !options.runner_flags.contains(RunnerFlags::DONT_TRAP_RDTSC) {
        disp.register_module(RdtscHandler::new());
    }

    #[cfg(target_arch = "x86_64")]
    if !options.runner_flags.contains(RunnerFlags::DONT_TRAP_CPUID) {
        disp.register_module(CpuidHandler::new());
    }

    // Segmentation
    if options.pmu_segmentation {
        disp.register_module(PmuSegmentor::new(
            options.checkpoint_period,
            options.pmu_segmentation_skip_instructions,
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

    // Dirty page trackers
    match options.dirty_page_tracker {
        DirtyPageAddressTrackerType::SoftDirty => {
            disp.register_module(SoftDirtyPageTracker::new(options.dont_clear_soft_dirty));
        }
        DirtyPageAddressTrackerType::Fpt => {
            disp.register_module(FptDirtyPageTracker::new());
        }
    }

    info!("Child process tracing started");

    let inferior = OwnedProcess::new(child_pid);

    let mut exit_status = None;

    let check_coord = CheckCoordinator::new(inferior, options.check_coord_flags, &disp);

    std::thread::scope(|scope| {
        let unwind_result = catch_unwind(AssertUnwindSafe(|| {
            let process_lifetime_hook_ctx = ProcessLifetimeHookContext {
                process: &check_coord.main,
                check_coord: &check_coord,
                scope,
            };

            disp.handle_main_init(process_lifetime_hook_ctx).unwrap();

            check_coord.main.resume().unwrap();

            let mut main_finished = false;
            let mut last_syscall_entry_handled_by_check_coord: HashMap<Pid, bool> = HashMap::new();

            loop {
                let status = waitpid(
                    None,
                    if options.runner_flags.contains(RunnerFlags::POLL_WAITPID) {
                        Some(WaitPidFlag::WNOHANG)
                    } else {
                        None
                    },
                )
                .unwrap();

                match status {
                    WaitStatus::Stopped(pid, sig) => {
                        check_coord.handle_signal(pid, sig, scope).unwrap();
                    }
                    WaitStatus::Exited(pid, status) => {
                        info!("Child {} exited", pid);
                        if pid == check_coord.main.pid {
                            main_finished = true;

                            disp.handle_main_fini(status, process_lifetime_hook_ctx)
                                .unwrap();

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
                        let regs = process.read_registers().unwrap();

                        if matches!(syscall_info.op, SyscallInfoOp::Entry { .. }) {
                            // syscall entry

                            if let Some(sysno) = regs.sysno() {
                                let args = regs.syscall_args();
                                check_coord
                                    .handle_syscall_entry(pid, sysno, args, scope)
                                    .unwrap();
                                last_syscall_entry_handled_by_check_coord.insert(pid, true);
                            } else {
                                let handled = disp
                                    .handle_custom_syscall_entry(
                                        regs.sysno_raw(),
                                        regs.syscall_args(),
                                        &HandlerContext {
                                            process: &process,
                                            segments: &check_coord.segments.read(),
                                            check_coord: &check_coord,
                                            scope,
                                        },
                                    )
                                    .unwrap();

                                if matches!(handled, SyscallHandlerExitAction::NextHandler) {
                                    // handle our custom syscalls
                                    match (regs.sysno_raw(), regs.syscall_args()) {
                                        (0xff77, ..) => {
                                            info!("Checkpoint requested by {}", pid);
                                            check_coord
                                                .handle_checkpoint(
                                                    pid,
                                                    false,
                                                    false,
                                                    CheckpointCaller::Child,
                                                    scope,
                                                )
                                                .unwrap();
                                        }
                                        (0xff78, ..) => {
                                            info!("Checkpoint finish requested by {}", pid);
                                            check_coord
                                                .handle_checkpoint(
                                                    pid,
                                                    true,
                                                    false,
                                                    CheckpointCaller::Child,
                                                    scope,
                                                )
                                                .unwrap();
                                        }
                                        (0xff79, ..) => {
                                            if pid == check_coord.main.pid {
                                                info!("Sync requested by main");
                                                check_coord.handle_sync().unwrap();
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
                                check_coord
                                    .handle_syscall_exit(pid, regs.syscall_ret_val(), scope)
                                    .unwrap();
                            } else {
                                disp.handle_custom_syscall_exit(
                                    regs.syscall_ret_val(),
                                    &HandlerContext {
                                        process: &process,
                                        segments: &check_coord.segments.read(),
                                        check_coord: &check_coord,
                                        scope,
                                    },
                                )
                                .unwrap();

                                ptrace::syscall(pid, None).unwrap();
                            }
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

                            check_coord.segments.read().lookup_segment_with(
                                pid,
                                |segment, is_main| {
                                    if is_main {
                                        panic!("Inferior unexpectedly killed by SIGKILL");
                                    } else {
                                        if !matches!(
                                            segment.status,
                                            segments::SegmentStatus::Checked { .. }
                                        ) {
                                            panic!("Checker {} unexpected killed by SIGKILL", pid);
                                        }
                                    }
                                },
                            );
                        } else {
                            panic!("PID {} signaled by {}", pid, sig);
                        }
                    }
                    _ => (),
                }
            }

            disp.handle_all_fini(process_lifetime_hook_ctx).unwrap();

            if options.runner_flags.contains(RunnerFlags::DUMP_STATS)
                || options.stats_output.is_some()
            {
                let mut s = statistics::as_text(disp.statistics());
                s.push_str("\n");

                if let Some(output_path) = options.stats_output {
                    fs::write(output_path, s).unwrap();
                } else {
                    print!("{}", s);
                }
            }
        }));

        if unwind_result.is_err() {
            disp.halt();
            panic!("Caught unwind");
        }
    });

    exit_status.unwrap()
}
