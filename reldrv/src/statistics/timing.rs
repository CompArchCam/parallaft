use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use itertools::Itertools;
use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        segment::SegmentEventHandler,
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::state::Stopped,
    types::{
        checker::CheckFailReason,
        exit_reason::ExitReason,
        process_id::{Checker, Main},
    },
};

use super::{StatisticValue, StatisticsProvider};

// Event hierarchy:
// * MainCheckpointing
//   * MainDirtyPageTracking
//   * MainForking
//   * MainThrottling [?]
//   * [other]
// * CheckerStarting
//   * CheckerForking
//   * CheckerReadyHook
// * CheckerWall
//   * CheckerUser
//   * CheckerSys
//   * CheckerSyscallEntryHandling
//   * CheckerSyscallExitHandling
//   * CheckerSignalHandling
//   * CheckerComparing

#[derive(Debug, PartialEq, Eq, Clone, Copy, PartialOrd, Ord, Hash)]
pub enum Event {
    // Main events
    MainCheckpointing,
    MainDirtyPageTracking,
    MainForking,
    MainThrottling,
    MainSyscallEntryHandling,
    MainSyscallExitHandling,
    MainSignalHandling,

    MainUser,
    MainSys,
    MainWall,

    // CheckerEvents
    CheckerStarting,
    CheckerForking,
    CheckerReadyHook,
    CheckerSyscallEntryHandling,
    CheckerSyscallExitHandling,
    CheckerSignalHandling,
    CheckerComparing,

    CheckerUser,
    CheckerSys,
    CheckerWall,

    // Misc
    AllWall,
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::MainCheckpointing => "main_checkpointing",
            Event::MainDirtyPageTracking => "main_dirty_page_tracking",
            Event::MainForking => "main_forking",
            Event::MainThrottling => "main_throttling",
            Event::MainSyscallEntryHandling => "main_syscall_entry_handling",
            Event::MainSyscallExitHandling => "main_syscall_exit_handling",
            Event::MainSignalHandling => "main_signal_handling",

            Event::MainUser => "main_user",
            Event::MainSys => "main_sys",
            Event::MainWall => "main_wall",

            Event::CheckerStarting => "checker_starting",
            Event::CheckerForking => "checker_forking",
            Event::CheckerReadyHook => "checker_ready_hook",
            Event::CheckerSyscallEntryHandling => "checker_syscall_entry_handling",
            Event::CheckerSyscallExitHandling => "checker_syscall_exit_handling",
            Event::CheckerSignalHandling => "checker_signal_handling",
            Event::CheckerComparing => "checker_comparing",

            Event::CheckerUser => "checker_user",
            Event::CheckerSys => "checker_sys",
            Event::CheckerWall => "checker_wall",

            Event::AllWall => "all_wall",
        }
    }
}

pub struct Tracer {
    durations: Mutex<HashMap<Event, Duration>>,
    exit_status: Mutex<Option<i32>>,
}

pub struct TracingGuard<'a> {
    start_instant: Instant,
    tracer: &'a Tracer,
    event: Event,
}

impl TracingGuard<'_> {
    pub fn end(self) {}
}

impl Drop for TracingGuard<'_> {
    fn drop(&mut self) {
        self.tracer.add(self.event, self.start_instant.elapsed());
    }
}

impl Tracer {
    pub fn new() -> Self {
        Self {
            durations: Mutex::new(HashMap::new()),
            exit_status: Mutex::new(None),
        }
    }

    pub fn trace(&self, event: Event) -> TracingGuard<'_> {
        TracingGuard {
            start_instant: Instant::now(),
            tracer: self,
            event,
        }
    }

    pub fn set(&self, event: Event, elapsed: Duration) {
        self.durations.lock().insert(event, elapsed);
    }

    pub fn add(&self, event: Event, elapsed: Duration) {
        let mut durations = self.durations.lock();
        *durations.entry(event).or_insert(Duration::ZERO) += elapsed;
    }
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

impl StatisticsProvider for Tracer {
    fn class_name(&self) -> &'static str {
        "timing"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn crate::statistics::StatisticValue>)]> {
        let mut stats: Vec<(String, Box<dyn StatisticValue>)> = vec![(
            "exit_status".to_owned(),
            Box::new(self.exit_status.lock().unwrap_or(255)),
        )];

        for (event, duration) in self.durations.lock().iter().sorted() {
            stats.push((
                event.name().to_owned() + "_time",
                Box::new(duration.as_secs_f64()),
            ));
        }

        stats.into_boxed_slice()
    }
}

fn ticks_to_duration(ticks: u64, tps: u64) -> Duration {
    Duration::from_secs_f64(ticks as f64 / tps as f64)
}

impl StandardSyscallHandler for Tracer {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        if !context.child.is_main() {
            return Ok(SyscallHandlerExitAction::NextHandler);
        }

        match syscall {
            Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                let ticks_per_second = procfs::ticks_per_second();
                let stats = context.process().stats()?;

                self.add(
                    Event::MainUser,
                    ticks_to_duration(stats.utime, ticks_per_second),
                );
                self.add(
                    Event::MainSys,
                    ticks_to_duration(stats.stime, ticks_per_second),
                );
            }
            _ => (),
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for Tracer {
    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        _main: &mut Main<Stopped>,
        exit_reason: &ExitReason,
        _context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        *self.exit_status.lock() = Some(exit_reason.exit_code());
        Ok(())
    }
}

impl SegmentEventHandler for Tracer {
    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
        _check_fail_reason: &Option<CheckFailReason>,
    ) -> Result<()> {
        let ticks_per_second = procfs::ticks_per_second();
        let stats = checker.process().stats()?;

        self.add(
            Event::CheckerUser,
            ticks_to_duration(stats.utime, ticks_per_second),
        );
        self.add(
            Event::CheckerSys,
            ticks_to_duration(stats.stime, ticks_per_second),
        );

        Ok(())
    }
}

impl Module for Tracer {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_process_lifetime_hook(self);
        subs.install_stats_providers(self);
        subs.install_segment_event_handler(self);
    }
}
