use log::info;
use nix::unistd::Pid;
use parking_lot::Mutex;
use perf_event::events::{Cache, CacheId, CacheOp, CacheResult};

use crate::dispatcher::{Dispatcher, Installable};
use crate::error::Result;
use crate::statistics::Statistics;
use crate::{process::Process, syscall_handlers::ProcessLifetimeHook};

use super::Value;

struct CacheCounters {
    ll_loads: perf_event::Counter,
    ll_load_misses: perf_event::Counter,
    ll_stores: perf_event::Counter,
    ll_store_misses: perf_event::Counter,

    dtlb_loads: perf_event::Counter,
    dtlb_load_misses: perf_event::Counter,
    dtlb_stores: perf_event::Counter,
    dtlb_store_misses: perf_event::Counter,
}

pub struct CacheStatsCollector {
    counters: Mutex<Option<CacheCounters>>,
}

impl CacheStatsCollector {
    pub fn new() -> Self {
        Self {
            counters: Mutex::new(None),
        }
    }

    fn init_perf_counters(&self, pid: Pid) -> Result<CacheCounters> {
        let ll_loads = perf_event::Builder::new(Cache {
            which: CacheId::LL,
            operation: CacheOp::READ,
            result: CacheResult::ACCESS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let ll_load_misses = perf_event::Builder::new(Cache {
            which: CacheId::LL,
            operation: CacheOp::READ,
            result: CacheResult::MISS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let ll_stores = perf_event::Builder::new(Cache {
            which: CacheId::LL,
            operation: CacheOp::WRITE,
            result: CacheResult::ACCESS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let ll_store_misses = perf_event::Builder::new(Cache {
            which: CacheId::LL,
            operation: CacheOp::WRITE,
            result: CacheResult::MISS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let dtlb_loads = perf_event::Builder::new(Cache {
            which: CacheId::DTLB,
            operation: CacheOp::READ,
            result: CacheResult::ACCESS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let dtlb_load_misses = perf_event::Builder::new(Cache {
            which: CacheId::DTLB,
            operation: CacheOp::READ,
            result: CacheResult::MISS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let dtlb_stores = perf_event::Builder::new(Cache {
            which: CacheId::DTLB,
            operation: CacheOp::WRITE,
            result: CacheResult::ACCESS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        let dtlb_store_misses = perf_event::Builder::new(Cache {
            which: CacheId::DTLB,
            operation: CacheOp::WRITE,
            result: CacheResult::MISS,
        })
        .observe_pid(pid.as_raw())
        .build()?;

        Ok(CacheCounters {
            ll_loads,
            ll_load_misses,
            ll_stores,
            ll_store_misses,

            dtlb_loads,
            dtlb_load_misses,
            dtlb_stores,
            dtlb_store_misses,
        })
    }
}

impl ProcessLifetimeHook for CacheStatsCollector {
    fn handle_main_init(&self, process: &Process) -> Result<()> {
        let mut group = self.counters.lock();
        let mut counters = self.init_perf_counters(process.pid).unwrap();

        counters.ll_loads.enable()?;
        counters.ll_load_misses.enable()?;
        counters.ll_stores.enable()?;
        counters.ll_store_misses.enable()?;

        counters.dtlb_loads.enable()?;
        counters.dtlb_load_misses.enable()?;
        counters.dtlb_stores.enable()?;
        counters.dtlb_store_misses.enable()?;

        *group = Some(counters);

        info!("Cache stats collector initialized");

        Ok(())
    }

    fn handle_main_fini(&self, _ret_val: i32) -> Result<()> {
        let mut group = self.counters.lock();
        let counters = group.as_mut().unwrap();

        counters.ll_loads.disable()?;
        counters.ll_load_misses.disable()?;
        counters.ll_stores.disable()?;
        counters.ll_store_misses.disable()?;

        counters.dtlb_loads.disable()?;
        counters.dtlb_load_misses.disable()?;
        counters.dtlb_stores.disable()?;
        counters.dtlb_store_misses.disable()?;

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

impl Statistics for CacheStatsCollector {
    fn class_name(&self) -> &'static str {
        "cache"
    }

    fn statistics(&self) -> Box<[(&'static str, Value)]> {
        let mut g = self.counters.lock();

        let counters = g.as_mut().unwrap();

        let ll_loads = scale(counters.ll_loads.read_count_and_time().unwrap());
        let ll_load_misses = scale(counters.ll_load_misses.read_count_and_time().unwrap());
        let ll_stores = scale(counters.ll_stores.read_count_and_time().unwrap());
        let ll_store_misses = scale(counters.ll_store_misses.read_count_and_time().unwrap());

        let dtlb_loads = scale(counters.dtlb_loads.read_count_and_time().unwrap());
        let dtlb_load_misses = scale(counters.dtlb_load_misses.read_count_and_time().unwrap());
        let dtlb_stores = scale(counters.dtlb_stores.read_count_and_time().unwrap());
        let dtlb_store_misses = scale(counters.dtlb_store_misses.read_count_and_time().unwrap());

        vec![
            ("llc_loads_u", Value::Int(ll_loads)),
            ("llc_load_misses_u", Value::Int(ll_load_misses)),
            ("llc_stores_u", Value::Int(ll_stores)),
            ("llc_store_misses_u", Value::Int(ll_store_misses)),
            ("dtlb_loads_u", Value::Int(dtlb_loads)),
            ("dtlb_load_misses_u", Value::Int(dtlb_load_misses)),
            ("dtlb_stores_u", Value::Int(dtlb_stores)),
            ("dtlb_store_misses_u", Value::Int(dtlb_store_misses)),
        ]
        .into_boxed_slice()
    }
}

impl<'a> Installable<'a> for CacheStatsCollector {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
