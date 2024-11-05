use log::{debug, info, warn};
use parking_lot::Mutex;
use std::collections::HashSet;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use super::{RunningAverage, StatisticValue, StatisticsProvider};
use crate::dispatcher::Subscribers;
use crate::events::module_lifetime::ModuleLifetimeHook;
use crate::events::process_lifetime::{HandlerContext, ProcessLifetimeHook};
use crate::process::dirty_pages::PageCategory;
use crate::process::state::Stopped;
use crate::process::Process;
use crate::statistics_list;
use crate::types::process_id::Main;
use crate::{dispatcher::Module, error::Result};

struct AverageAndPeak {
    average: RunningAverage,
    peak: Mutex<u64>,
}

impl AverageAndPeak {
    fn new() -> Self {
        Self {
            average: RunningAverage::new(),
            peak: Mutex::new(0),
        }
    }

    fn update(&self, value: u64) {
        self.average.update(value as _);
        let mut peak = self.peak.lock();
        if value > *peak {
            *peak = value;
        }
    }

    fn get(&self) -> (f64, u64) {
        (self.average.get(), *self.peak.lock())
    }
}

pub struct MemoryCollector {
    interval: Duration,
    pss: AverageAndPeak,
    checkpoint_private_dirty: AverageAndPeak,
    working_set_upper_lim: AverageAndPeak, // pss - checkpoint_private_dirty
    num_samples: AtomicUsize,
    worker: Mutex<Option<Sender<()>>>,
    include_rt: bool,
    allow_pagemap_scan: bool,
}

impl MemoryCollector {
    pub fn new(interval: Duration, include_rt: bool, allow_pagemap_scan: bool) -> Self {
        Self {
            interval,
            pss: AverageAndPeak::new(),
            checkpoint_private_dirty: AverageAndPeak::new(),
            working_set_upper_lim: AverageAndPeak::new(),
            num_samples: AtomicUsize::new(0),
            worker: Mutex::new(None),
            include_rt,
            allow_pagemap_scan,
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
                let mut checkpoint_processes = vec![];

                let mut checkpoints = HashSet::new();

                for segment in &segments.list {
                    processes.extend(segment.checker_processes());

                    if let Some(p) = segment.checkpoint_end() {
                        checkpoints.insert(p);
                    };

                    checkpoints.insert(segment.checkpoint_start.clone());
                }

                for checkpoint in checkpoints {
                    if let Some(p) = checkpoint.process.lock().as_ref() {
                        checkpoint_processes.push(p.unowned_copy());
                    }
                }

                if self.include_rt {
                    processes.push(Process::shell());
                }

                drop(segments);

                let mut pss = 0;
                let mut checkpoint_private_dirty = 0;

                for process in processes {
                    if let Ok(stats) = process.memory_stats() {
                        pss += stats.pss + stats.swap_pss;
                    }
                }

                for process in checkpoint_processes {
                    if let Ok(stats) = process.memory_stats() {
                        pss += stats.pss + stats.swap_pss;
                        if stats.swap_pss > 0 {
                            if self.allow_pagemap_scan {
                                let mut s = 0;

                                process.for_each_writable_map(|map| {
                                    if let Ok(result) = process.pagemap_scan(
                                        map.address.0 as _,
                                        map.address.1 as _,
                                        PageCategory::empty(),
                                        PageCategory::UNIQUE,
                                        PageCategory::empty(),
                                        PageCategory::UNIQUE,
                                    ) {
                                        s += result.iter().map(|(r, _)| (r.end - r.start) as u64).sum::<u64>();
                                    }

                                    Ok(())
                                }, &[]).ok();

                                checkpoint_private_dirty += s;
                            }
                            else {
                                warn!("Swap PSS detected for checkpointed process, but pagemap scan is disabled. This will lead to inaccurate checkpoint_private_dirty.");
                                checkpoint_private_dirty += stats.private_dirty;
                            }
                        } else {
                            checkpoint_private_dirty += stats.private_dirty;
                        }
                    }
                }

                debug!("Sampled PSS = {}", pss);
                debug!(
                    "Sampled checkpoint private dirty = {}",
                    checkpoint_private_dirty
                );

                self.pss.update(pss);
                self.checkpoint_private_dirty
                    .update(checkpoint_private_dirty);
                self.working_set_upper_lim
                    .update(pss - checkpoint_private_dirty);

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
        let (pss_average, pss_peak) = self.pss.get();
        let (checkpoint_private_dirty_average, checkpoint_private_dirty_peak) =
            self.checkpoint_private_dirty.get();
        let (working_set_upper_lim_average, working_set_upper_lim_peak) =
            self.working_set_upper_lim.get();

        statistics_list!(
            pss_average = pss_average,
            pss_peak = pss_peak,
            checkpoint_private_dirty_average = checkpoint_private_dirty_average,
            checkpoint_private_dirty_peak = checkpoint_private_dirty_peak,
            working_set_upper_lim_average = working_set_upper_lim_average,
            working_set_upper_lim_peak = working_set_upper_lim_peak,
            num_samples = self.num_samples.load(Ordering::SeqCst)
        )
    }
}

impl ModuleLifetimeHook for MemoryCollector {
    fn fini<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
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
