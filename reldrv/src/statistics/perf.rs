use clap::ValueEnum;
use log::info;
use nix::unistd::Pid;
use parking_lot::Mutex;
use perf_event::events::{Cache, CacheId, CacheOp, CacheResult, Hardware};

use crate::dispatcher::{Dispatcher, Installable};
use crate::error::Result;
use crate::statistics::Statistics;
use crate::syscall_handlers::HandlerContext;
use crate::syscall_handlers::ProcessLifetimeHook;

use super::Value;

#[derive(Debug, Clone, Copy, ValueEnum)]
pub enum CounterKind {
    LLLoads,
    LLLoadMisses,
    LLStores,
    LLStoreMisses,
    DTLBLoads,
    DTLBLoadMisses,
    DTLBStores,
    DTLBStoreMisses,
    Instructions,
}

impl CounterKind {
    fn to_str(self) -> &'static str {
        match self {
            CounterKind::LLLoads => "ll_loads",
            CounterKind::LLLoadMisses => "ll_load_misses",
            CounterKind::LLStores => "ll_stores",
            CounterKind::LLStoreMisses => "ll_store_misses",
            CounterKind::DTLBLoads => "dtlb_loads",
            CounterKind::DTLBLoadMisses => "dtlb_load_misses",
            CounterKind::DTLBStores => "dtlb_stores",
            CounterKind::DTLBStoreMisses => "dtlb_store_misses",
            CounterKind::Instructions => "instructions",
        }
    }

    fn build_perf_event_counter(self, pid: Pid) -> std::io::Result<perf_event::Counter> {
        match self {
            CounterKind::LLLoads => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::READ,
                result: CacheResult::ACCESS,
            }),
            CounterKind::LLLoadMisses => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::READ,
                result: CacheResult::MISS,
            }),
            CounterKind::LLStores => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::WRITE,
                result: CacheResult::ACCESS,
            }),
            CounterKind::LLStoreMisses => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::WRITE,
                result: CacheResult::MISS,
            }),
            CounterKind::DTLBLoads => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::READ,
                result: CacheResult::ACCESS,
            }),
            CounterKind::DTLBLoadMisses => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::READ,
                result: CacheResult::MISS,
            }),
            CounterKind::DTLBStores => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::WRITE,
                result: CacheResult::ACCESS,
            }),
            CounterKind::DTLBStoreMisses => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::WRITE,
                result: CacheResult::MISS,
            }),
            CounterKind::Instructions => perf_event::Builder::new(Hardware::INSTRUCTIONS),
        }
        .observe_pid(pid.as_raw())
        .build()
    }
}

pub struct PerfStatsCollector {
    counters: Mutex<Vec<perf_event::Counter>>,
    counter_kinds: Vec<CounterKind>,
}

impl PerfStatsCollector {
    pub fn new(enabled_counters: Vec<CounterKind>) -> Self {
        Self {
            counters: Mutex::new(Vec::new()),
            counter_kinds: enabled_counters,
        }
    }
}

impl ProcessLifetimeHook for PerfStatsCollector {
    fn handle_main_init(&self, context: &HandlerContext) -> Result<()> {
        let process = context.process;
        let mut group = self.counters.lock();
        let mut counters = self
            .counter_kinds
            .iter()
            .map(|c| c.build_perf_event_counter(process.pid))
            .collect::<std::io::Result<Vec<_>>>()?;

        counters
            .iter_mut()
            .map(|c| c.enable())
            .collect::<std::io::Result<Vec<_>>>()?;

        *group = counters;

        info!("Cache stats collector initialized");

        Ok(())
    }

    fn handle_main_fini(&self, _ret_val: i32, _context: &HandlerContext) -> Result<()> {
        let mut group = self.counters.lock();

        group
            .iter_mut()
            .map(|c| c.disable())
            .collect::<std::io::Result<Vec<_>>>()?;

        Ok(())
    }
}

fn scale(count: perf_event::CountAndTime) -> u64 {
    if count.time_running == 0 {
        0
    } else {
        (count.count as u128 * count.time_enabled as u128 / count.time_running as u128) as u64
    }
}

impl Statistics for PerfStatsCollector {
    fn class_name(&self) -> &'static str {
        "perf"
    }

    fn statistics(&self) -> Box<[(&'static str, Value)]> {
        let mut g = self.counters.lock();

        self.counter_kinds
            .iter()
            .map(|s| s.to_str())
            .zip(
                g.iter_mut()
                    .map(|c| Value::Int(scale(c.read_count_and_time().unwrap())))
                    .collect::<Vec<_>>(),
            )
            .collect::<Vec<_>>()
            .into_boxed_slice()
    }
}

impl<'a> Installable<'a> for PerfStatsCollector {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
