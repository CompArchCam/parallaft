use log::{debug, info};
use parking_lot::Mutex;
use std::sync::atomic::{AtomicUsize, Ordering};
use std::sync::mpsc::{channel, RecvTimeoutError, Sender};
use std::time::Duration;

use super::{RunningAverage, StatisticValue, Statistics};
use crate::dispatcher::{Dispatcher, Halt};
use crate::process::{Process, ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::{dispatcher::Installable, error::Result};

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
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
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
                        let segment = segment.lock();

                        if let Some(p) = segment.checker() {
                            pids.push(p.pid);
                        }

                        if let Some(p) = segment.reference_end() {
                            pids.push(p.pid);
                        }
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
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
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

impl Statistics for MemoryCollector {
    fn class_name(&self) -> &'static str {
        "memory"
    }

    fn statistics(&self) -> Box<[(&'static str, Box<dyn StatisticValue>)]> {
        Box::new([
            ("pss_average", Box::new(self.pss_average.get())),
            ("pss_peak", Box::new(*self.pss_peak.lock())),
            (
                "num_samples",
                Box::new(self.num_samples.load(Ordering::SeqCst)),
            ),
        ])
    }
}

impl<'a> Installable<'a> for MemoryCollector {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
        dispatcher.install_halt_hook(self);
    }
}
