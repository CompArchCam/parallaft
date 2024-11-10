use log::debug;
use perf_event::SampleSkid;

#[cfg(target_arch = "x86_64")]
mod x86_64 {
    #[derive(Debug, PartialEq, Eq, Clone, Copy)]
    pub enum IntelCoreType {
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
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, Hash)]
pub enum CpuModel {
    #[cfg(target_arch = "x86_64")]
    Amd,
    #[cfg(target_arch = "x86_64")]
    IntelMont,
    #[cfg(target_arch = "x86_64")]
    IntelLakeCove,
    #[cfg(target_arch = "x86_64")]
    IntelOther,

    #[cfg(target_arch = "aarch64")]
    Armv8CortexA76,
    #[cfg(target_arch = "aarch64")]
    Armv8NeoverseN1,
    #[cfg(target_arch = "aarch64")]
    Armv8NeoverseV2,
    #[cfg(target_arch = "aarch64")]
    AppleAvalancheM2,
    #[cfg(target_arch = "aarch64")]
    AppleBlizzardM2,

    Unknown,
}

impl CpuModel {
    #[cfg(target_arch = "x86_64")]
    pub fn detect(processor_id: usize) -> Self {
        use nix::{
            sched::{sched_getaffinity, sched_setaffinity, CpuSet},
            unistd::Pid,
        };
        use scopeguard::defer;

        use self::x86_64::IntelCoreType;

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
                    (0x6, 0x7, IntelCoreType::Atom) => Self::IntelMont,
                    (0x6, 0x7, _) => Self::IntelLakeCove,
                    _ => Self::IntelOther,
                }
            }
            _ => Self::Unknown,
        }
    }

    #[cfg(target_arch = "aarch64")]
    pub fn detect(processor_id: usize) -> Self {
        let midr_el1 = u64::from_str_radix(
            &std::fs::read_to_string(format!(
                "/sys/devices/system/cpu/cpu{processor_id}/regs/identification/midr_el1"
            ))
            .expect("Failed to read MIDR_EL1 register")
            .trim_end()
            .strip_prefix("0x")
            .unwrap(),
            16,
        )
        .expect("Failed to parse MIDR_EL1 register");

        debug!("Detected CPU{} MIDR_EL1 = {:#x}", processor_id, midr_el1);

        let part_num = (midr_el1 >> 4) & 0xfff;
        debug!("Detected CPU{} part number = {:#x}", processor_id, part_num);

        let implementer = (midr_el1 >> 24) & 0xff;
        debug!(
            "Detected CPU{} implementor = {:#x}",
            processor_id, implementer
        );

        Self::from_midr_el1_implementer_and_part_num(implementer, part_num)
    }

    #[cfg(target_arch = "aarch64")]
    pub fn from_midr_el1_implementer_and_part_num(implementer: u64, part: u64) -> Self {
        // https://github.com/util-linux/util-linux/blob/master/sys-utils/lscpu-arm.c
        match (implementer, part) {
            // Implementer: Arm Limited.
            (0x41, 0xd0b) => Self::Armv8CortexA76,
            (0x41, 0xd0c) => Self::Armv8NeoverseN1,
            (0x41, 0xd4f) => Self::Armv8NeoverseV2,
            (0x61, 0x033) => Self::AppleAvalancheM2,
            (0x61, 0x032) => Self::AppleBlizzardM2,
            _ => Self::Unknown,
        }
    }

    pub fn max_skid(&self) -> u64 {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Amd => 2048,
            #[cfg(target_arch = "x86_64")]
            Self::IntelLakeCove | Self::IntelMont | Self::IntelOther => 2048, // orig: 1024
            #[cfg(target_arch = "aarch64")]
            Self::Armv8CortexA76
            | Self::Armv8NeoverseN1
            | Self::Armv8NeoverseV2
            | Self::AppleAvalancheM2
            | Self::AppleBlizzardM2 => 512, // TODO: verify this
            _ => 0,
        }
    }

    pub fn min_irq_period(&self) -> u64 {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::Amd => 16384, // TODO: verify this
            #[cfg(target_arch = "x86_64")]
            Self::IntelLakeCove | Self::IntelMont | Self::IntelOther => 16384,
            #[cfg(target_arch = "aarch64")]
            Self::Armv8CortexA76
            | Self::Armv8NeoverseN1
            | Self::Armv8NeoverseV2
            | Self::AppleAvalancheM2
            | Self::AppleBlizzardM2 => 16384, // TODO: verify this
            _ => 0,
        }
    }

    pub fn max_sample_skid(&self) -> SampleSkid {
        match self {
            #[cfg(target_arch = "x86_64")]
            Self::IntelLakeCove | Self::IntelMont | Self::IntelOther => SampleSkid::RequireZero,
            _ => SampleSkid::RequestZero,
        }
    }
}

#[cfg(test)]
mod tests {
    use nix::unistd::{sysconf, SysconfVar};

    use super::*;

    #[test]
    fn test_detect_cpu_model() {
        for i in 0..sysconf(SysconfVar::_NPROCESSORS_CONF).unwrap().unwrap() as usize {
            let model = CpuModel::detect(i);
            println!("CPU {i} model is {model:?}");
        }
    }
}
