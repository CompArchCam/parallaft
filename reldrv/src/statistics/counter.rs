use std::sync::atomic::{AtomicU64, Ordering};

use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::Result,
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction,
        SYSNO_CHECKPOINT_FINI, SYSNO_CHECKPOINT_TAKE,
    },
};

use super::{timing::TimingCollector, Statistics, Value};

pub struct CounterCollector<'a> {
    checkpoint_count: AtomicU64,
    syscall_count: AtomicU64,
    timing_collector: &'a TimingCollector,
}

impl<'a> CounterCollector<'a> {
    pub fn new(timing_collector: &'a TimingCollector) -> CounterCollector {
        CounterCollector {
            checkpoint_count: AtomicU64::new(0),
            syscall_count: AtomicU64::new(0),
            timing_collector,
        }
    }
}

impl<'a> Statistics for CounterCollector<'a> {
    fn name(&self) -> &'static str {
        "counter"
    }

    fn statistics(&self) -> Box<[(&'static str, Value)]> {
        let checkpoint_count = self.checkpoint_count.load(Ordering::SeqCst);
        let syscall_count = self.syscall_count.load(Ordering::SeqCst);

        let main_wall_time = self.timing_collector.main_wall_time().as_secs_f64();

        vec![
            ("checkpoint_count", Value::Int(checkpoint_count)),
            ("syscall_count", Value::Int(syscall_count)),
            (
                "checkpoint_frequency",
                Value::Float(checkpoint_count as f64 / main_wall_time),
            ),
        ]
        .into_boxed_slice()
    }
}

impl<'a> StandardSyscallHandler for CounterCollector<'a> {
    fn handle_standard_syscall_entry(
        &self,
        _syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if context.process.pid == context.check_coord.main.pid {
            self.syscall_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> CustomSyscallHandler for CounterCollector<'a> {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if context.process.pid == context.check_coord.main.pid
            && (sysno == SYSNO_CHECKPOINT_TAKE || sysno == SYSNO_CHECKPOINT_FINI)
        {
            self.checkpoint_count.fetch_add(1, Ordering::SeqCst);
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a, 'c> Installable<'a> for CounterCollector<'c> {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
        dispatcher.install_custom_syscall_handler(self);
    }
}
