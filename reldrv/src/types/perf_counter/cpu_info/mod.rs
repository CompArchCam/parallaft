mod cpu_model;
pub mod pmu;

pub use cpu_model::CpuModel;
use pmu::PMUS;

use std::{collections::HashMap, path::PathBuf};

use nix::unistd::{sysconf, SysconfVar};

pub struct CpuInfo {
    pub id: usize,
    pub model: CpuModel,
    pub pmu_name: Option<PathBuf>,
}

pub fn detect_all_cpu_info() -> HashMap<usize, CpuInfo> {
    let pmus = &*PMUS;
    let mut cpu_info = HashMap::new();

    for cpu in 0..sysconf(SysconfVar::_NPROCESSORS_CONF).unwrap().unwrap() as usize {
        let model = CpuModel::detect(cpu);
        cpu_info.insert(
            cpu,
            CpuInfo {
                id: cpu,
                model,
                pmu_name: pmus
                    .iter()
                    .find(|p| p.cpus.contains(&cpu))
                    .map(|p| p.name.clone()),
            },
        );
    }

    cpu_info
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_detect_all_cpu_info() {
        let cpu_info = detect_all_cpu_info();
        assert!(!cpu_info.is_empty());
    }
}
