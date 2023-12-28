use crate::dispatcher::Dispatcher;
use crate::process::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::{dispatcher::Installable, error::Result};

use super::{RunningAverage, StatisticValue, Statistics};

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
    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        nr_dirty_pages: Option<usize>,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        if let Some(nr_dirty_pages) = nr_dirty_pages {
            self.avg.update(nr_dirty_pages as _);
        }

        Ok(())
    }
}

impl Statistics for DirtyPageStatsCollector {
    fn class_name(&self) -> &'static str {
        "dirty_pages"
    }

    fn statistics(&self) -> Box<[(&'static str, Box<dyn StatisticValue>)]> {
        Box::new([("nr_dirty_pages", Box::new(self.avg.get()))])
    }
}

impl<'a> Installable<'a> for DirtyPageStatsCollector {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
