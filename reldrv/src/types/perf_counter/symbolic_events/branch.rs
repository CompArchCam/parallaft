use cfg_if::cfg_if;
use clap::ValueEnum;
use nix::unistd::Pid;
use perf_event::SampleSkid;

use crate::{
    error::Result,
    impl_perf_counter, impl_perf_counter_with_interrupt,
    types::perf_counter::{cpu_info::CpuModel, PerfCounter, PerfCounterWithInterrupt},
};

use super::{
    expr::{lookup_cpu_model_and_pmu_name_from_cpu_set, Target},
    Expr,
};

fn get_expr(branch_type: BranchType, cpu_model: CpuModel) -> Expr {
    cfg_if! {
        if #[cfg(target_arch = "aarch64")] {
            match (branch_type, cpu_model) {
                (BranchType::AllExclFar, CpuModel::Armv8CortexA55) => Expr::Subtract(
                    Box::new(Expr::Dynamic("br_retired")),
                    Box::new(Expr::Dynamic("exc_taken")),
                ),
                (BranchType::AllExclFar, CpuModel::Armv8CortexA76) => Expr::Dynamic("br_retired"),
                _ => todo!(),
            }
        }
        else if #[cfg(target_arch = "x86_64")] {
            todo!()
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum BranchType {
    #[default]
    AllExclFar,
    Cond,
    CondTaken,
}

pub struct BranchCounter {
    counter: Box<dyn PerfCounter>,
}

impl BranchCounter {
    pub fn new(
        branch_type: BranchType,
        target: Target,
        pinned: bool,
        cpu_set: &[usize],
    ) -> Result<Self> {
        let (cpu_model, pmu) = lookup_cpu_model_and_pmu_name_from_cpu_set(cpu_set)?;

        Ok(Self {
            counter: get_expr(branch_type, cpu_model).build(pmu, target, pinned)?,
        })
    }
}

impl_perf_counter!(BranchCounter, counter);

pub struct BranchCounterWithInterrupt {
    counter: Box<dyn PerfCounterWithInterrupt>,
}

impl BranchCounterWithInterrupt {
    pub fn new(
        branch_type: BranchType,
        pid: Pid,
        pinned: bool,
        cpu_set: &[usize],
        irq_period: u64,
        sample_skid: Option<SampleSkid>,
    ) -> Result<Self> {
        let (cpu_model, pmu) = lookup_cpu_model_and_pmu_name_from_cpu_set(cpu_set)?;

        Ok(Self {
            counter: get_expr(branch_type, cpu_model).build_with_interrupt(
                pmu,
                pid,
                pinned,
                irq_period,
                sample_skid.unwrap_or_else(|| cpu_model.max_sample_skid()),
            )?,
        })
    }
}

impl_perf_counter!(BranchCounterWithInterrupt, counter);
impl_perf_counter_with_interrupt!(BranchCounterWithInterrupt, counter);
