use std::{collections::HashMap, fs};

use cfg_if::cfg_if;
use lazy_static::lazy_static;
use log::{debug, warn};
use nix::{
    sched::{sched_getaffinity, sched_setaffinity, CpuSet},
    unistd::Pid,
};
use parking_lot::Mutex;
use scopeguard::defer;

#[cfg(target_arch = "aarch64")]
use super::linux::constants;

lazy_static! {
    static ref PMU_TYPE_MAP: Mutex<HashMap<usize, PmuType>> = Mutex::new(HashMap::new());
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
enum IntelCoreType {
    Atom,
    Core,
    Other,
}

impl From<u32> for IntelCoreType {
    fn from(value: u32) -> Self {
        match value {
            0x20 => Self::Atom,
            0x40 => Self::Core,
            _ => Self::Other,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum PmuType {
    // TODO: more precise model detection
    #[cfg(target_arch = "x86_64")]
    Amd,
    #[cfg(target_arch = "x86_64")]
    IntelMont {
        in_hybrid: bool,
    },
    #[cfg(target_arch = "x86_64")]
    IntelLakeCove,
    #[cfg(target_arch = "x86_64")]
    IntelOther,

    #[cfg(target_arch = "aarch64")]
    Armv8CortexA55,
    #[cfg(target_arch = "aarch64")]
    Armv8CortexA76,
    #[cfg(target_arch = "aarch64")]
    ArmOther,

    Unknown,
}

impl PmuType {
    #[cfg(target_arch = "x86_64")]
    fn detect_single_x86_64(processor_id: usize) -> Self {
        let pid_self = Pid::from_raw(0);
        let mut cpu_set = CpuSet::new();
        cpu_set.set(processor_id).unwrap();

        let old_cpu_set = sched_getaffinity(pid_self).unwrap();
        sched_setaffinity(pid_self, &cpu_set).unwrap();

        defer! {
            sched_setaffinity(pid_self, &old_cpu_set).unwrap();
        };

        let cpuid0 = unsafe { std::arch::x86_64::__cpuid(0) };

        // detect CPU vendor
        let mut vendor = [0; 12];
        vendor[0..4].copy_from_slice(&cpuid0.ebx.to_le_bytes());
        vendor[4..8].copy_from_slice(&cpuid0.edx.to_le_bytes());
        vendor[8..12].copy_from_slice(&cpuid0.ecx.to_le_bytes());

        let max_leaf = cpuid0.eax;
        let vendor = std::str::from_utf8(&vendor).unwrap_or_default();
        let cpuid1 = unsafe { std::arch::x86_64::__cpuid(1) };
        let model = (cpuid1.eax >> 4) & 0xf;
        let family_id = (cpuid1.eax >> 8) & 0xf;

        debug!("Detected CPU{} vendor = {}", processor_id, vendor);
        debug!("Detected CPU{} model = {:x}", processor_id, model);
        debug!("Detected CPU{} family ID = {:x}", processor_id, family_id);

        match vendor {
            "AuthenticAMD" => Self::Amd,
            "GenuineIntel" => {
                let cpuid7 = unsafe { std::arch::x86_64::__cpuid(0x7) };
                let is_hybrid = (cpuid7.edx >> 15) & 1 > 0;

                let mut core_type = IntelCoreType::Other;

                if is_hybrid && max_leaf >= 0x1a {
                    let cpuid1a = unsafe { std::arch::x86_64::__cpuid(0x1a) };
                    if cpuid1a.eax != 0 {
                        // Native Model ID Enumeration Leaf exists
                        core_type = ((cpuid1a.eax >> 24) & 0xff).into();
                        debug!("Detected CPU{} core type = {:?}", processor_id, core_type);
                    }
                }

                match (family_id, model, core_type) {
                    (0x6, 0x7, IntelCoreType::Atom) => Self::IntelMont { in_hybrid: true },
                    (0x6, 0x7, _) => Self::IntelLakeCove,
                    _ => Self::IntelOther,
                }
            }
            _ => Self::Unknown,
        }
    }

    #[cfg(target_arch = "aarch64")]
    fn detect_all_aarch64(map: &mut HashMap<usize, PmuType>) {
        for dir in fs::read_dir("/sys/bus/event_source/devices")
            .expect("Cannot access /sys/bus/event_source/devices")
        {
            if let Ok(dir) = dir {
                let path = dir.path();
                let cpus_path = path.join("cpus");
                if path.is_dir() && cpus_path.is_file() {
                    let pmu_name = dir.file_name().into_string().unwrap();
                    let contents = fs::read_to_string(cpus_path).unwrap();
                    let mut cpus: Vec<usize> = contents
                        .trim_end()
                        .split("-")
                        .map(|x| x.parse::<usize>().unwrap())
                        .collect();

                    assert!(cpus.len() == 1 || cpus.len() == 2);

                    if cpus.len() == 2 {
                        let start = cpus[0];
                        let end = cpus[1];
                        cpus = (start..=end).collect();
                    }

                    let pmu_type = match pmu_name.as_str() {
                        constants::ARMV8_CORTEX_A55 => Self::Armv8CortexA55,
                        constants::ARMV8_CORTEX_A76 => Self::Armv8CortexA76,
                        _ => Self::ArmOther,
                    };

                    for cpu in cpus {
                        map.insert(cpu, pmu_type);
                    }
                }
            }
        }
    }

    pub fn detect(processor_id: usize) -> PmuType {
        cfg_if! {
            if #[cfg(target_arch = "x86_64")] {
                let mut map = PMU_TYPE_MAP.lock();

                if let Some(pmu_type) = map.get(&processor_id) {
                    *pmu_type
                }
                else {
                    let pmu_type = Self::detect_single_x86_64(processor_id);
                    map.insert(processor_id, pmu_type);
                    pmu_type
                }
            }
            else if #[cfg(target_arch = "aarch64")] {
                let mut map = PMU_TYPE_MAP.lock();
                if map.is_empty() {
                    Self::detect_all_aarch64(&mut map);
                }
                *map.get(&processor_id).unwrap_or(&PmuType::ArmOther)
            }
            else {
                unreachable!()
            }
        }
    }

    pub fn max_skid(&self) -> u64 {
        match self {
            #[cfg(target_arch = "x86_64")]
            PmuType::Amd => 2048,
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelLakeCove | PmuType::IntelMont { .. } | PmuType::IntelOther => 2048, // orig: 1024
            #[cfg(target_arch = "aarch64")]
            PmuType::Armv8CortexA55 | PmuType::Armv8CortexA76 => 512,
            _ => 0,
        }
    }

    pub fn min_irq_period(&self) -> u64 {
        match self {
            #[cfg(target_arch = "x86_64")]
            PmuType::Amd => 16384, // TODO: verify this
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelLakeCove | PmuType::IntelMont { .. } | PmuType::IntelOther => 16384,
            #[cfg(target_arch = "aarch64")]
            PmuType::Armv8CortexA55 | PmuType::Armv8CortexA76 => 16384, // TODO: verify this
            _ => 0,
        }
    }
}
