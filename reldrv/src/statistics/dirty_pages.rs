use crate::dispatcher::Subscribers;
use crate::events::process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::statistics_list;
use crate::{dispatcher::Module, error::Result};

use super::{RunningAverage, StatisticValue, StatisticsProvider};

pub struct DirtyPageStatsCollector {
    avg: RunningAverage,
}

impl Default for DirtyPageStatsCollector {
    fn default() -> Self {
        Self::new()
    }
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
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
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

impl StatisticsProvider for DirtyPageStatsCollector {
    fn class_name(&self) -> &'static str {
        "dirty_pages"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        statistics_list!(nr_dirty_pages = self.avg.get())
    }
}

impl Module for DirtyPageStatsCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_stats_providers(self);
    }
}
