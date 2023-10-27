pub mod check_coord;
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
use std::path::PathBuf;

use bitflags::bitflags;

use nix::errno::Errno;
use nix::sys::ptrace::{self, SyscallInfoOp};
use nix::sys::signal::Signal;
use nix::sys::wait::{waitpid, WaitPidFlag, WaitStatus};
use nix::unistd::Pid;

use log::{info, warn};
use statistics::perf::CounterKind;

use crate::check_coord::{CheckCoordinator, CheckCoordinatorFlags};
use crate::dispatcher::{Dispatcher, Installable};
use crate::helpers::affinity::AffinitySetter;
use crate::helpers::checkpoint_size_limiter::CheckpointSizeLimiter;
use crate::helpers::vdso::VdsoRemover;
use crate::inferior_rtlib::legacy::LegacyInferiorRtLib;
use crate::inferior_rtlib::relrtlib::RelRtLib;
use crate::process::{OwnedProcess, Process};
use crate::segments::CheckpointCaller;
use crate::signal_handlers::cpuid::CpuidHandler;
use crate::signal_handlers::rdtsc::RdtscHandler;
use crate::statistics::counter::CounterCollector;
use crate::statistics::dirty_pages::DirtyPageStatsCollector;
use crate::statistics::perf::PerfStatsCollector;
use crate::statistics::timing::TimingCollector;
use crate::statistics::StatisticsSet;
use crate::syscall_handlers::clone::CloneHandler;
use crate::syscall_handlers::execve::ExecveHandler;
use crate::syscall_handlers::exit::ExitHandler;
use crate::syscall_handlers::mmap::MmapHandler;
use crate::syscall_handlers::replicate::ReplicatedSyscallHandler;
use crate::syscall_handlers::rseq::RseqHandler;
use crate::syscall_handlers::{
    CustomSyscallHandler, HandlerContext, ProcessLifetimeHook, SyscallHandlerExitAction,
};
use crate::throttlers::memory::MemoryBasedThrottler;
use crate::throttlers::nr_segments::NrSegmentsBasedThrottler;

bitflags! {
    pub struct RunnerFlags: u32 {
        const POLL_WAITPID = 0b00000001;
        const DUMP_STATS = 0b00000010;
        const DONT_TRAP_RDTSC = 0b00000100;
        const DONT_TRAP_CPUID = 0b00001000;
    }
}

pub struct RelShellOptions {
    pub runner_flags: RunnerFlags,
    pub check_coord_flags: CheckCoordinatorFlags,
    pub stats_output: Option<PathBuf>,

    // librelrt plugin options
    pub librelrt_checkpoint_period: u64,

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

    // checkpoint size limiter plugin options
    pub checkpoint_size_watermark: usize,

    // perf counter plugin options
    pub enabled_perf_counters: Vec<CounterKind>,
}

impl Default for RelShellOptions {
    fn default() -> Self {
        Self {
            runner_flags: RunnerFlags::empty(),
            check_coord_flags: CheckCoordinatorFlags::empty(),
            stats_output: None,
            librelrt_checkpoint_period: 0,
            max_nr_live_segments: 0,
            memory_overhead_watermark: 0,
            main_cpu_set: Vec::new(),
            checker_cpu_set: Vec::new(),
            shell_cpu_set: Vec::new(),
            cache_masks: None,
            checkpoint_size_watermark: 0,
            enabled_perf_counters: Vec::new(),
        }
    }
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

    let mut disp = Dispatcher::new();
    let rseq_handler = RseqHandler::new();
    rseq_handler.install(&mut disp);

    let clone_handler = CloneHandler::new();
    clone_handler.install(&mut disp);

    let execve_handler = ExecveHandler::new();
    execve_handler.install(&mut disp);

    let exit_handler = ExitHandler::new();
    exit_handler.install(&mut disp);

    let mmap_handler = MmapHandler::new();
    mmap_handler.install(&mut disp);

    let replicated_syscall_handler = ReplicatedSyscallHandler::new();
    replicated_syscall_handler.install(&mut disp);

    let rdtsc_handler = RdtscHandler::new();

    if !options.runner_flags.contains(RunnerFlags::DONT_TRAP_RDTSC) {
        rdtsc_handler.install(&mut disp);
    }

    let cpuid_handler = CpuidHandler::new();

    if !options.runner_flags.contains(RunnerFlags::DONT_TRAP_CPUID) {
        cpuid_handler.install(&mut disp);
    }

    let legacy_rtlib_handler = LegacyInferiorRtLib::new();
    legacy_rtlib_handler.install(&mut disp);

    let relrtlib_handler = RelRtLib::new(options.librelrt_checkpoint_period);
    relrtlib_handler.install(&mut disp);

    let vdso_remover = VdsoRemover::new();
    vdso_remover.install(&mut disp);

    #[cfg(not(feature = "intel_cat"))]
    let affinity_setter = AffinitySetter::new(&options.main_cpu_set, &options.checker_cpu_set);

    #[cfg(feature = "intel_cat")]
    let affinity_setter = AffinitySetter::new_with_cache_allocation(
        &options.main_cpu_set,
        &options.checker_cpu_set,
        &options.shell_cpu_set,
        options.cache_masks,
    );

    affinity_setter.install(&mut disp);

    let checkpoint_size_limiter = CheckpointSizeLimiter::new(options.checkpoint_size_watermark);
    checkpoint_size_limiter.install(&mut disp);

    let time_stats = TimingCollector::new();
    time_stats.install(&mut disp);

    let counter_stats = CounterCollector::new(&time_stats);
    counter_stats.install(&mut disp);

    let cache_stats = PerfStatsCollector::new(options.enabled_perf_counters);
    cache_stats.install(&mut disp);

    let dirty_page_stats = DirtyPageStatsCollector::new();
    dirty_page_stats.install(&mut disp);

    let all_stats = StatisticsSet::new(vec![
        &time_stats,
        &counter_stats,
        &cache_stats,
        &dirty_page_stats,
        &checkpoint_size_limiter,
    ]);

    let memory_based_throttler = MemoryBasedThrottler::new(options.memory_overhead_watermark);
    memory_based_throttler.install(&mut disp);

    let nr_segment_based_throttler = NrSegmentsBasedThrottler::new(options.max_nr_live_segments);
    nr_segment_based_throttler.install(&mut disp);

    info!("Child process tracing started");

    let inferior = OwnedProcess::new(child_pid);

    disp.handle_main_init(&inferior).unwrap();
    let mut exit_status = None;

    let check_coord = CheckCoordinator::new(inferior, options.check_coord_flags, &disp);

    std::thread::scope(|scope| {
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
                    check_coord.handle_signal(pid, sig).unwrap();
                }
                WaitStatus::Exited(pid, status) => {
                    info!("Child {} exited", pid);
                    if pid == check_coord.main.pid {
                        main_finished = true;

                        disp.handle_main_fini(status).unwrap();

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
                                        check_coord: &check_coord,
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
                                    check_coord: &check_coord,
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

                        check_coord
                            .segments
                            .get_active_segment_with(pid, |segment, is_main| {
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
                            });
                    } else {
                        panic!("PID {} signaled by {}", pid, sig);
                    }
                }
                _ => (),
            }
        }

        disp.handle_all_fini().unwrap();

        if options.runner_flags.contains(RunnerFlags::DUMP_STATS) || options.stats_output.is_some()
        {
            let _nr_checkpoints = check_coord.epoch();

            let mut s = all_stats.as_text();
            s.push_str("\n");

            if let Some(output_path) = options.stats_output {
                fs::write(output_path, s).unwrap();
            } else {
                print!("{}", s);
            }
        }
    });

    exit_status.unwrap()
}
