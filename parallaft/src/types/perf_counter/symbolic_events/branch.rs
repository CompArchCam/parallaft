use cfg_if::cfg_if;
use clap::ValueEnum;
use nix::unistd::Pid;
use perf_event::SampleSkid;
use serde::{Deserialize, Serialize};

use crate::{
    error::Result,
    impl_perf_counter, impl_perf_counter_with_interrupt,
    types::perf_counter::{cpu_info::CpuModel, PerfCounter, PerfCounterWithInterrupt},
};

use super::{
    expr::{lookup_cpu_model_and_pmu_name_from_cpu_set, Target},
    Expr,
};

mod constants {
    cfg_if::cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            pub const AMD_EX_RET_BRN: u64 = 0xc2;
            pub const AMD_EX_RET_BRN_FAR: u64 = 0xc6;
            pub const INTEL_BR_INST_RETIRED_ALL_BRANCHES: u64 = 0x00c4;
            pub const INTEL_LAKE_COVE_BR_INST_RETIRED_FAR_BRANCH: u64 = 0x40c4;
            pub const INTEL_MONT_BR_INST_RETIRED_FAR_BRANCH: u64 = 0xbfc4;
            pub const INTEL_LAKE_COVE_BR_INST_RETIRED_COND: u64 = 0x11c4;
            pub const INTEL_MONT_BR_INST_RETIRED_COND: u64 = 0x7ec4;
            pub const INTEL_LAKE_COVE_BR_INST_RETIRED_COND_TAKEN: u64 = 0x01c4;
            pub const INTEL_MONT_BR_INST_RETIRED_COND_TAKEN: u64 = 0xfec4;
        }
        else if #[cfg(target_arch = "aarch64")] {
            pub const ARM_BR_RETIRED: &'static str = "br_retired";
            pub const APPLE_BR_RETIRED: u64 = 0x8d;
        }
    }
}

fn get_expr(branch_type: BranchType, cpu_model: CpuModel) -> Expr {
    cfg_if! {
        if #[cfg(target_arch = "aarch64")] {
            match (branch_type, cpu_model) {

                (BranchType::AllExclFar, CpuModel::Armv8CortexA76 | CpuModel::Armv8NeoverseN1 | CpuModel::Armv8NeoverseV2) => Expr::Dynamic(constants::ARM_BR_RETIRED),
                (BranchType::AllExclFar, CpuModel::AppleAvalancheM2 | CpuModel::AppleBlizzardM2) => Expr::Raw(constants::APPLE_BR_RETIRED),
                _ => todo!(),
            }
        }
        else if #[cfg(target_arch = "x86_64")] {
            match (branch_type, cpu_model) {
                (BranchType::AllExclFar, CpuModel::Amd) => Expr::Subtract(
                    Box::new(Expr::Raw(constants::AMD_EX_RET_BRN)),
                    Box::new(Expr::Raw(constants::AMD_EX_RET_BRN_FAR))
                ),
                (BranchType::AllExclFar, CpuModel::IntelLakeCove) => Expr::Subtract(
                    Box::new(Expr::Raw(constants::INTEL_BR_INST_RETIRED_ALL_BRANCHES)),
                    Box::new(Expr::Raw(constants::INTEL_LAKE_COVE_BR_INST_RETIRED_FAR_BRANCH))
                ),
                (BranchType::AllExclFar, CpuModel::IntelMont) => Expr::Subtract(
                    Box::new(Expr::Raw(constants::INTEL_BR_INST_RETIRED_ALL_BRANCHES)),
                    Box::new(Expr::Raw(constants::INTEL_MONT_BR_INST_RETIRED_FAR_BRANCH))
                ),
                (BranchType::Cond, CpuModel::IntelLakeCove) => Expr::Raw(constants::INTEL_LAKE_COVE_BR_INST_RETIRED_COND),
                (BranchType::Cond, CpuModel::IntelMont) => Expr::Raw(constants::INTEL_MONT_BR_INST_RETIRED_COND),
                (BranchType::CondTaken, CpuModel::IntelLakeCove) => Expr::Raw(constants::INTEL_LAKE_COVE_BR_INST_RETIRED_COND_TAKEN),
                (BranchType::CondTaken, CpuModel::IntelMont) => Expr::Raw(constants::INTEL_MONT_BR_INST_RETIRED_COND_TAKEN),
                _ => todo!(),
            }
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum, Serialize, Deserialize)]
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
