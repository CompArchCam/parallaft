use parking_lot::Mutex;

use crate::dispatcher::Dispatcher;
use crate::process::Process;
use crate::syscall_handlers::ProcessLifetimeHook;
use crate::{dispatcher::Installable, error::Result};

use super::{Statistics, Value};

struct RunningAverage {
    data: Mutex<(f64, usize)>,
}

impl RunningAverage {
    pub fn new() -> Self {
        Self {
            data: Mutex::new((0.0, 0)),
        }
    }
    pub fn get(&self) -> f64 {
        self.data.lock().0
    }

    pub fn update(&self, value: f64) {
        let mut data = self.data.lock();
        let (avg, cnt) = &mut *data;

        *cnt += 1;
        *avg = (1.0 / *cnt as f64) * value + (1.0 - 1.0 / *cnt as f64);
    }
}

pub struct DirtyPageStatsCollector {
    avg: RunningAverage,
}

impl DirtyPageStatsCollector {
    pub fn new() -> Self {
        Self {
            avg: RunningAverage::new(),
        }
    }
}

impl ProcessLifetimeHook for DirtyPageStatsCollector {
    fn handle_checker_fini(&self, _process: &Process, nr_dirty_pages: Option<usize>) -> Result<()> {
        if let Some(nr_dirty_pages) = nr_dirty_pages {
            self.avg.update(nr_dirty_pages as _);
        }

        Ok(())
    }
}

impl Statistics for DirtyPageStatsCollector {
    fn name(&self) -> &'static str {
        "dirty_pages"
    }

    fn statistics(&self) -> Box<[(&'static str, Value)]> {
        vec![("nr_dirty_pages", Value::Float(self.avg.get()))].into_boxed_slice()
    }
}

impl<'a> Installable<'a> for DirtyPageStatsCollector {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
