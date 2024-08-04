use crate::dispatcher::Subscribers;
use crate::events::process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::statistics_list;
use crate::types::checker::CheckerStatus;
use crate::types::process_id::Checker;
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
        checker: &mut Checker,
        _context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        let checker_status = checker.segment.checker_status.lock();

        if let CheckerStatus::Checked {
            dirty_page_addresses,
            ..
        } = &*checker_status
        {
            self.avg
                .update(dirty_page_addresses.addresses.as_ref().as_ref().len() as _);
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
