use log::{debug, info};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use super::{RunningAverage, StatisticValue, StatisticsProvider};
use crate::dispatcher::{Halt, Subscribers};
use crate::events::process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::process::Process;
use crate::statistics_list;
use crate::{dispatcher::Module, error::Result};

pub struct MemoryCollector {
    interval: Duration,
    pss_average: RunningAverage,
    pss_peak: Mutex<usize>,
    num_samples: AtomicUsize,
    worker: Mutex<Option<Sender<()>>>,
    include_rt: bool,
}

impl MemoryCollector {
    pub fn new(interval: Duration, include_rt: bool) -> Self {
        Self {
            interval,
            pss_average: RunningAverage::new(),
            pss_peak: Mutex::new(0),
            num_samples: AtomicUsize::new(0),
            worker: Mutex::new(None),
            include_rt,
        }
    }
}

impl ProcessLifetimeHook for MemoryCollector {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        info!("Memory sampler started");

        let (tx, rx) = channel();
        context.scope.spawn(move || loop {
            // TODO: join handle
            match rx.recv_timeout(self.interval) {
                Err(RecvTimeoutError::Timeout) => {
                    let segments = context.check_coord.segments.read();
                    let mut pids = vec![context.check_coord.main.pid];

                    for segment in &segments.list {
                        let segment = segment.read();

                        if let Some(p) = segment.checker.process() {
                            pids.push(p.pid);
                        }

                        if let Some(p) = segment.reference_end() {
                            pids.push(p.pid);
                        };
                    }

                    if self.include_rt {
                        pids.push(Process::shell().pid);
                    }

                    drop(segments);

                    let pss = pids
                        .iter()
                        .map(|&pid| Process::new(pid).pss().unwrap_or(0)) // Process may die at this point
                        .sum::<usize>();

                    debug!("Sampled PSS = {}", pss);

                    self.pss_average.update(pss as _);
                    let mut pss_peak = self.pss_peak.lock();

                    if pss > *pss_peak {
                        *pss_peak = pss;
                    }

                    self.num_samples.fetch_add(1, Ordering::SeqCst);
                }
                _ => {
                    break;
                }
            }
        });

        *self.worker.lock() = Some(tx);

        Ok(())
    }

    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.halt();
        Ok(())
    }
}

impl Halt for MemoryCollector {
    fn halt(&self) {
        let mut worker = self.worker.lock();
        if let Some(stop) = worker.take() {
            stop.send(()).unwrap();
        }
    }
}

impl StatisticsProvider for MemoryCollector {
    fn class_name(&self) -> &'static str {
        "memory"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        statistics_list!(
            pss_average = self.pss_average.get(),
            pss_peak = *self.pss_peak.lock(),
            num_samples = self.num_samples.load(Ordering::SeqCst)
        )
    }
}

impl Module for MemoryCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_halt_hook(self);
        subs.install_stats_providers(self);
    }
}
