use std::{
    sync::{
        atomic::AtomicU32,
        mpsc::{channel, RecvTimeoutError, Sender},
    },
    thread::Scope,
    time::Duration,
};

use log::debug;
use nix::unistd::Pid;
use parking_lot::Mutex;
use perf_event::events::Hardware;
use reverie_syscalls::Syscall;
use try_insert_ext::OptionInsertExt;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        module_lifetime::ModuleLifetimeHook,
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        segment::SegmentEventHandler,
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::Process,
    signal_handlers::{
        begin_protection::main_begin_protection_req, slice_segment::main_enqueue_slice_segment_req,
    },
    syscall_handlers::is_execve_ok,
    types::{
        perf_counter::{self, linux::LinuxPerfCounter, pmu_type::PmuType, PerfCounter},
        process_id::Main,
    },
};

#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DynamicSlicerParams {
    /// Sample period
    sample_period: Duration,
    /// Min allowed cycles in a segment
    min_cycles_in_segment: Option<u64>,
    /// Max allowed cycles in a segment
    max_cycles_in_segment: Option<u64>,
    /// Max allowed fork and copy-on-write (COW) cost fraction
    fork_cow_cost_threshold_fraction: f64,
    /// Number of cycles executed per copy-on-write (COW) operation
    nr_cycles_per_cow_op: f64,
    /// Number of cycles executed per fork operation per page
    nr_cycles_per_fork_per_page: f64,
}

impl Default for DynamicSlicerParams {
    fn default() -> Self {
        Self {
            sample_period: Duration::from_secs_f32(0.5),
            min_cycles_in_segment: Some(1_000_000_000),
            max_cycles_in_segment: Some(500_000_000_000),
            fork_cow_cost_threshold_fraction: 0.1,
            nr_cycles_per_cow_op: 10000.0,
            nr_cycles_per_fork_per_page: 800.0,
        }
    }
}

pub struct DynamicSlicer {
    params: DynamicSlicerParams,
    worker: Mutex<Option<Sender<()>>>,
    main_cycles_counter: Mutex<Option<Box<dyn PerfCounter>>>,
    main_pmu_type: PmuType,
    epoch: AtomicU32,
}

impl DynamicSlicer {
    pub fn new(main_cpu_set: &[usize]) -> Self {
        Self {
            params: DynamicSlicerParams::default(),
            worker: Mutex::new(None),
            main_cycles_counter: Mutex::new(None),
            main_pmu_type: PmuType::detect(*main_cpu_set.first().unwrap_or(&0)),
            epoch: AtomicU32::new(0),
        }
    }

    fn should_slice_segment(&self, main_pid: Pid) -> Result<bool> {
        let main_cycles = self.main_cycles_counter.lock().as_mut().unwrap().read()?;

        if let Some(max_cycles) = self.params.max_cycles_in_segment {
            if main_cycles > max_cycles {
                debug!(
                    "Slicing segment due to too many cycles executed ({} > {})",
                    main_cycles, max_cycles
                );
                return Ok(true);
            }
        }

        if let Some(min_cycles) = self.params.min_cycles_in_segment {
            if main_cycles < min_cycles {
                debug!(
                    "Deferring slicing segment due to too few cycles executed ({} < {})",
                    main_cycles, min_cycles
                );
                return Ok(false);
            }
        }

        if main_cycles > 0 {
            let memory_stats = Process::new(main_pid).memory_stats()?;

            let fork_cow_cost_fraction = (memory_stats.dirty_pages as f64
                * self.params.nr_cycles_per_cow_op
                + memory_stats.rss_pages as f64 * self.params.nr_cycles_per_fork_per_page)
                / main_cycles as f64;

            if fork_cow_cost_fraction >= self.params.fork_cow_cost_threshold_fraction {
                debug!(
                    "Deferring slicing due to fork and COW cost too high ({} > {})",
                    fork_cow_cost_fraction, self.params.fork_cow_cost_threshold_fraction
                );
                return Ok(false);
            } else {
                debug!(
                    "Slicing segment due to low fork and COW cost ({} < {})",
                    fork_cow_cost_fraction, self.params.fork_cow_cost_threshold_fraction
                );
                return Ok(true);
            }
        }

        Ok(false)
    }
}

impl SegmentEventHandler for DynamicSlicer {
    fn handle_checkpoint_created_pre(&self, main: &mut Main) -> Result<()> {
        self.main_cycles_counter
            .lock()
            .get_or_try_insert_with(|| -> Result<_> {
                Ok(Box::new(LinuxPerfCounter::count_hw_events(
                    Hardware::CPU_CYCLES,
                    self.main_pmu_type,
                    false,
                    perf_counter::linux::Target::Pid(main.process.pid),
                )?))
            })?
            .reset()?;

        Ok(())
    }
}

impl StandardSyscallHandler for DynamicSlicer {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            assert!(context.child.is_main());
            main_begin_protection_req(context.child.process().pid)?;
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for DynamicSlicer {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope + 'disp,
        'disp: 'scope,
    {
        let (tx, rx) = channel();
        *self.worker.lock() = Some(tx);

        let segments = context.check_coord.segments.clone();
        let main_pid = context.process.pid;

        context.scope.spawn(move || {
            (|| -> Result<()> {
                while let Err(RecvTimeoutError::Timeout) =
                    rx.recv_timeout(self.params.sample_period)
                {
                    if let Some(segment) = segments.read().main_segment() {
                        if (segment.nr > self.epoch.load(std::sync::atomic::Ordering::SeqCst)
                            || segment.nr == 0)
                            && self.should_slice_segment(main_pid)?
                        {
                            self.epoch
                                .store(segment.nr, std::sync::atomic::Ordering::SeqCst);
                            main_enqueue_slice_segment_req(main_pid)?;
                        }
                    }
                }
                Ok(())
            })()
            .expect("Dynamic slicer crashed");
        });
        Ok(())
    }
}

impl ModuleLifetimeHook for DynamicSlicer {
    fn fini<'s, 'scope, 'env>(&'s self, _scope: &'scope Scope<'scope, 'env>) -> Result<()>
    where
        's: 'scope,
    {
        let worker = self.worker.lock();

        if let Some(tx) = worker.as_ref() {
            tx.send(()).expect("Failed to stop worker");
        }

        Ok(())
    }
}

impl Module for DynamicSlicer {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_standard_syscall_handler(self);
        subs.install_process_lifetime_hook(self);
        subs.install_module_lifetime_hook(self);
    }
}
