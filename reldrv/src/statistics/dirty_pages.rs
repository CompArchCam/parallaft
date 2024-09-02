use std::sync::atomic::{AtomicU64, Ordering};

use crate::dispatcher::Subscribers;
use crate::events::process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::process::state::Stopped;
use crate::process::PAGESIZE;
use crate::statistics_list;
use crate::types::checker::CheckerStatus;
use crate::types::process_id::Checker;
use crate::{dispatcher::Module, error::Result};

use super::{StatisticValue, StatisticsProvider};

pub struct DirtyPageStatsCollector {
    total_dirty_pages: AtomicU64,
}

impl Default for DirtyPageStatsCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl DirtyPageStatsCollector {
    pub fn new() -> Self {
        Self {
            total_dirty_pages: AtomicU64::new(0),
        }
    }
}

impl ProcessLifetimeHook for DirtyPageStatsCollector {
    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker<Stopped>,
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
            self.total_dirty_pages.fetch_add(
                dirty_page_addresses
                    .addresses
                    .iter()
                    .map(|x| (x.end - x.start) / *PAGESIZE)
                    .sum::<usize>() as _,
                Ordering::SeqCst,
            );
        }

        Ok(())
    }
}

impl StatisticsProvider for DirtyPageStatsCollector {
    fn class_name(&self) -> &'static str {
        "dirty_pages"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        statistics_list!(total_dirty_pages = self.total_dirty_pages.load(Ordering::SeqCst))
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
