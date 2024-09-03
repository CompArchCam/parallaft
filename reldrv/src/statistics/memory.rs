use log::{debug, info};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use super::{RunningAverage, StatisticValue, StatisticsProvider};
use crate::dispatcher::Subscribers;
use crate::events::module_lifetime::ModuleLifetimeHook;
use crate::events::process_lifetime::{HandlerContext, ProcessLifetimeHook};
use crate::process::state::Stopped;
use crate::process::Process;
use crate::statistics_list;
use crate::types::process_id::Main;
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
        _main: &mut Main<Stopped>,
        context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        info!("Memory sampler started");

        let (tx, rx) = channel();
        context.scope.spawn(move || {
            while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(self.interval) {
                // TODO: join handle
                let segments = context.check_coord.segments.read();
                let mut processes = vec![context.check_coord.main.clone()];

                let mut checkpoints = HashSet::new();

                for segment in &segments.list {
                    if let Some(p) = segment.checker_status.lock().process() {
                        processes.push(p.clone());
                    }

                    if let Some(p) = segment.checkpoint_end() {
                        checkpoints.insert(p);
                    };

                    checkpoints.insert(segment.checkpoint_start.clone());
                }

                for checkpoint in checkpoints {
                    if let Some(p) = checkpoint.process.lock().as_ref() {
                        processes.push(p.unowned_copy());
                    }
                }

                if self.include_rt {
                    processes.push(Process::shell());
                }

                drop(segments);

                let pss = processes
                    .iter()
                    .map(|p| p.memory_stats().map(|x| x.pss).unwrap_or(0)) // Process may die at this point
                    .sum::<usize>();

                debug!("Sampled PSS = {}", pss);

                self.pss_average.update(pss as _);
                let mut pss_peak = self.pss_peak.lock();

                if pss > *pss_peak {
                    *pss_peak = pss;
                }

                self.num_samples.fetch_add(1, Ordering::SeqCst);
            }
        });

        *self.worker.lock() = Some(tx);

        Ok(())
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

impl ModuleLifetimeHook for MemoryCollector {
    fn fini<'s, 'scope, 'env>(
        &'s self,
        _scope: &'scope std::thread::Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
    {
        let mut worker = self.worker.lock();
        if let Some(stop) = worker.take() {
            stop.send(()).unwrap();
        }
        Ok(())
    }
}

impl Module for MemoryCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_module_lifetime_hook(self);
        subs.install_process_lifetime_hook(self);
        subs.install_stats_providers(self);
    }
}
