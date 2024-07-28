mod base;
mod sub;

use std::{
    error::Error,
    fmt::{self, Display, Formatter},
    path::PathBuf,
};

pub use base::{BasePerfCounter, BasePerfCounterWithInterrupt};
use itertools::Itertools;
use nix::unistd::Pid;
use perf_event::{events::Hardware, SampleSkid};
pub use sub::{SubstractPerfCounter, SubstractPerfCounterWithInterrupt};

use crate::types::perf_counter::{
    cpu_info::CpuModel, raw_events::EVENT_CACHE, PerfCounter, PerfCounterWithInterrupt,
    CPU_INFO_MAP,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Pid(Pid),
    Cpu(usize),
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Expr {
    // Hardware event
    Hardware(Hardware),
    // Raw event
    Raw(u64),
    // Dynamic event
    Dynamic(&'static str),
    // Subtract two events
    Subtract(Box<Expr>, Box<Expr>),
}

impl Expr {
    pub fn build(
        self,
        pmu: impl Into<PathBuf>,
        target: Target,
        pinned: bool,
    ) -> std::io::Result<Box<dyn PerfCounter>> {
        let pmu = pmu.into();

        Ok(match self {
            Expr::Hardware(hardware) => Box::new(BasePerfCounter::new(
                EVENT_CACHE.hardware_under_pmu(&pmu, hardware)?,
                target,
                pinned,
            )?),
            Expr::Raw(raw) => Box::new(BasePerfCounter::new(
                EVENT_CACHE.raw_under_pmu(&pmu, raw)?,
                target,
                pinned,
            )?),
            Expr::Dynamic(name) => Box::new(BasePerfCounter::new(
                EVENT_CACHE.dynamic(&pmu, name)?,
                target,
                pinned,
            )?),
            Expr::Subtract(lhs, rhs) => {
                let lhs = lhs.build(&pmu, target, pinned)?;
                let rhs = rhs.build(&pmu, target, pinned)?;
                Box::new(SubstractPerfCounter(lhs, rhs))
            }
        })
    }

    pub fn build_with_interrupt(
        self,
        pmu: impl Into<PathBuf>,
        pid: Pid,
        pinned: bool,
        irq_period: u64,
        sample_skid: SampleSkid,
    ) -> std::io::Result<Box<dyn PerfCounterWithInterrupt>> {
        let pmu = pmu.into();

        Ok(match self {
            Expr::Hardware(hardware) => Box::new(BasePerfCounterWithInterrupt::new(
                EVENT_CACHE.hardware_under_pmu(&pmu, hardware)?,
                pid,
                pinned,
                irq_period,
                sample_skid,
            )?),
            Expr::Raw(raw) => Box::new(BasePerfCounterWithInterrupt::new(
                EVENT_CACHE.raw_under_pmu(&pmu, raw)?,
                pid,
                pinned,
                irq_period,
                sample_skid,
            )?),
            Expr::Dynamic(name) => Box::new(BasePerfCounterWithInterrupt::new(
                EVENT_CACHE.dynamic(&pmu, name)?,
                pid,
                pinned,
                irq_period,
                sample_skid,
            )?),
            Expr::Subtract(lhs, rhs) => {
                let lhs = lhs.build_with_interrupt(&pmu, pid, pinned, irq_period, sample_skid)?;
                let rhs = rhs.build(&pmu, Target::Pid(pid), pinned)?;
                Box::new(SubstractPerfCounterWithInterrupt(lhs, rhs))
            }
        })
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PmuError {
    PmuDoesNotExist,
    MixedPmuTypeOrCpuModel,
}

impl Display for PmuError {
    fn fmt(&self, f: &mut Formatter<'_>) -> fmt::Result {
        #[allow(deprecated)]
        self.description().fmt(f)
    }
}

impl Error for PmuError {
    fn description(&self) -> &str {
        match self {
            PmuError::PmuDoesNotExist => "PMU does not exist",
            PmuError::MixedPmuTypeOrCpuModel => "Mixed PMU type or CPU model",
        }
    }
}

pub fn lookup_cpu_model_and_pmu_name_from_cpu_set(
    cpu_set: &[usize],
) -> Result<(CpuModel, PathBuf), PmuError> {
    cpu_set
        .iter()
        .map(|cpu| CPU_INFO_MAP.get(cpu).expect("CPU does not exist"))
        .map(|cpu_info| (cpu_info.model, cpu_info.pmu_name.clone()))
        .all_equal_value()
        .map_err(|_| PmuError::MixedPmuTypeOrCpuModel)
        .and_then(|(cpu_model, pmu_name)| {
            if let Some(pmu_name) = pmu_name {
                Ok((cpu_model, pmu_name))
            } else {
                Err(PmuError::PmuDoesNotExist)
            }
        })
}
