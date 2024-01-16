use clap::ValueEnum;
use log::info;
use nix::unistd::Pid;
use parking_lot::Mutex;
use perf_event::events::{Cache, CacheId, CacheOp, CacheResult, DynamicBuilder, Hardware};

use crate::dispatcher::{Module, Subscribers};
use crate::error::Result;
use crate::process::{ProcessLifetimeHook, ProcessLifetimeHookContext};
use crate::statistics::StatisticsProvider;

use super::StatisticValue;

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
    EnergyCores,
    EnergyPkg,
    EnergyRam,
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
            CounterKind::EnergyCores => "energy_cores",
            CounterKind::EnergyPkg => "energy_pkg",
            CounterKind::EnergyRam => "energy_ram",
        }
    }

    fn build_perf_event_counter(self, pid: Pid) -> std::io::Result<perf_event::Counter> {
        match self {
            CounterKind::LLLoads => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::READ,
                result: CacheResult::ACCESS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::LLLoadMisses => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::READ,
                result: CacheResult::MISS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::LLStores => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::WRITE,
                result: CacheResult::ACCESS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::LLStoreMisses => perf_event::Builder::new(Cache {
                which: CacheId::LL,
                operation: CacheOp::WRITE,
                result: CacheResult::MISS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::DTLBLoads => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::READ,
                result: CacheResult::ACCESS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::DTLBLoadMisses => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::READ,
                result: CacheResult::MISS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::DTLBStores => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::WRITE,
                result: CacheResult::ACCESS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::DTLBStoreMisses => perf_event::Builder::new(Cache {
                which: CacheId::DTLB,
                operation: CacheOp::WRITE,
                result: CacheResult::MISS,
            })
            .observe_pid(pid.as_raw())
            .build(),
            CounterKind::Instructions => perf_event::Builder::new(Hardware::INSTRUCTIONS)
                .observe_pid(pid.as_raw())
                .build(),
            CounterKind::EnergyCores => perf_event::Builder::new(
                DynamicBuilder::new("power")?
                    .event("energy-cores")?
                    .build()?,
            )
            .include_hv()
            .include_kernel()
            .observe_pid(-1)
            .one_cpu(0)
            .build(),
            CounterKind::EnergyPkg => perf_event::Builder::new(
                DynamicBuilder::new("power")?.event("energy-pkg")?.build()?,
            )
            .include_hv()
            .include_kernel()
            .observe_pid(-1)
            .one_cpu(0)
            .build(),
            CounterKind::EnergyRam => perf_event::Builder::new(
                DynamicBuilder::new("power")?.event("energy-ram")?.build()?,
            )
            .include_hv()
            .include_kernel()
            .observe_pid(-1)
            .one_cpu(0)
            .build(),
        }
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
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
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

    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        _ret_val: i32,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
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

impl StatisticsProvider for PerfStatsCollector {
    fn class_name(&self) -> &'static str {
        "perf"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        let mut g = self.counters.lock();

        self.counter_kinds
            .iter()
            .map(|s| s.to_str().to_owned())
            .zip(
                g.iter_mut()
                    .map(|c| {
                        let t: Box<dyn StatisticValue> =
                            Box::new(scale(c.read_count_and_time().unwrap()));
                        t
                    })
                    .collect::<Vec<_>>(),
            )
            .collect::<Box<[(String, Box<dyn StatisticValue>)]>>()
    }
}

impl Module for PerfStatsCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_stats_providers(self);
    }
}
