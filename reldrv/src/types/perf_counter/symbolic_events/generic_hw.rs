use nix::unistd::Pid;
use perf_event::SampleSkid;

use crate::{
    error::Result,
    impl_perf_counter, impl_perf_counter_with_interrupt,
    types::perf_counter::{
        cpu_info::pmu::PMUS, raw_events::Hardware, PerfCounter, PerfCounterWithInterrupt,
    },
};

use super::{
    expr::{lookup_cpu_model_and_pmu_name_from_cpu_set, Target},
    Expr,
};

pub struct GenericHardwareEventCounter {
    counter: Box<dyn PerfCounter>,
}

impl GenericHardwareEventCounter {
    pub fn new(
        event: Hardware,
        target: Target,
        pinned: bool,
        cpu_set: Option<&[usize]>,
    ) -> Result<Self> {
        if let Some(cpu_set) = cpu_set {
            let (_, pmu) = lookup_cpu_model_and_pmu_name_from_cpu_set(cpu_set)?;

            Ok(Self {
                counter: Expr::Hardware(event).build(pmu, target, pinned)?,
            })
        } else {
            let pmus = PMUS.iter().map(|p| p.name.clone()).collect::<Vec<_>>();

            Ok(Self {
                counter: Expr::Hardware(event).build_multiple_pmus(pmus, target, pinned)?,
            })
        }
    }
}

impl_perf_counter!(GenericHardwareEventCounter, counter);

pub struct GenericHardwareEventCounterWithInterrupt {
    counter: Box<dyn PerfCounterWithInterrupt>,
}

impl GenericHardwareEventCounterWithInterrupt {
    pub fn new(
        event: Hardware,
        pid: Pid,
        pinned: bool,
        cpu_set: &[usize],
        irq_period: u64,
        sample_skid: Option<SampleSkid>,
    ) -> Result<Self> {
        let (cpu_model, pmu) = lookup_cpu_model_and_pmu_name_from_cpu_set(cpu_set)?;

        Ok(Self {
            counter: Expr::Hardware(event).build_with_interrupt(
                pmu,
                pid,
                pinned,
                irq_period,
                sample_skid.unwrap_or_else(|| cpu_model.max_sample_skid()),
            )?,
        })
    }
}

impl_perf_counter!(GenericHardwareEventCounterWithInterrupt, counter);
impl_perf_counter_with_interrupt!(GenericHardwareEventCounterWithInterrupt, counter);
