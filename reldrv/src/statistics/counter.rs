use std::sync::atomic::{AtomicU64, Ordering};

use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    statistics_list,
};

use super::{StatisticValue, StatisticsProvider};

pub struct CounterCollector {
    checkpoint_count: AtomicU64,
    syscall_count: AtomicU64,
}

impl CounterCollector {
    pub fn new() -> CounterCollector {
        CounterCollector {
            checkpoint_count: AtomicU64::new(0),
            syscall_count: AtomicU64::new(0),
        }
    }
}

impl StatisticsProvider for CounterCollector {
    fn class_name(&self) -> &'static str {
        "counter"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        statistics_list!(
            checkpoint_count = self.checkpoint_count.load(Ordering::SeqCst),
            syscall_count = self.syscall_count.load(Ordering::SeqCst)
        )
    }
}

impl StandardSyscallHandler for CounterCollector {
    fn handle_standard_syscall_entry(
        &self,
        _syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if context.child.is_main() {
            self.syscall_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for CounterCollector {
    fn handle_all_fini<'s, 'scope, 'disp, 'modules>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, 'modules>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        let epoch = context.check_coord.epoch();
        self.checkpoint_count.store(epoch as _, Ordering::SeqCst);
        Ok(())
    }
}

impl Module for CounterCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_process_lifetime_hook(self);
        subs.install_stats_providers(self);
    }
}
