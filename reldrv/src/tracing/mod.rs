use std::{
    collections::HashMap,
    time::{Duration, Instant},
};

use parking_lot::Mutex;

use crate::{
    dispatcher::Module,
    statistics::{StatisticValue, StatisticsProvider},
};

// Event hierarchy:
// * Checkpointing
//   * DirtyPageTracking
//   * Forking
//   * Throttling [?]
//   * [other]
// * SyscallEntryHandling
// * SyscallExitHandling
// * SignalHandling

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum Event {
    DirtyPageTracking,
    Checkpointing,
    Throttling,
    Forking,
    SyscallEntryHandling,
    SyscallExitHandling,
    SignalHandling,
}

impl Event {
    pub fn name(&self) -> &'static str {
        match self {
            Event::DirtyPageTracking => "dirty_page_tracking",
            Event::Checkpointing => "checkpointing",
            Event::SyscallEntryHandling => "syscall_entry_handling",
            Event::SyscallExitHandling => "syscall_exit_handling",
            Event::SignalHandling => "signal_handling",
            Event::Throttling => "throttling",
            Event::Forking => "forking",
        }
    }
}

pub struct Tracer {
    durations: Mutex<HashMap<Event, Duration>>,
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
        let elapsed = self.start_instant.elapsed();

        let mut durations = self.tracer.durations.lock();
        let duration = durations.entry(self.event).or_insert(Duration::ZERO);

        *duration += elapsed;
    }
}

impl Tracer {
    pub fn new() -> Self {
        Self {
            durations: Mutex::new(HashMap::new()),
        }
    }

    pub fn trace(&self, event: Event) -> TracingGuard<'_> {
        TracingGuard {
            start_instant: Instant::now(),
            tracer: self,
            event,
        }
    }
}

impl Default for Tracer {
    fn default() -> Self {
        Self::new()
    }
}

impl StatisticsProvider for Tracer {
    fn class_name(&self) -> &'static str {
        "tracer"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn crate::statistics::StatisticValue>)]> {
        let mut stats: Vec<(String, Box<dyn StatisticValue>)> = Vec::new();

        for (event, duration) in self.durations.lock().iter() {
            stats.push((
                event.name().to_owned() + "_time",
                Box::new(duration.as_secs_f64()),
            ));
        }

        stats.into_boxed_slice()
    }
}

impl Module for Tracer {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_stats_providers(self);
    }
}
