use log::debug;

use nix::{
    sched::{sched_getaffinity, sched_setaffinity, CpuSet},
    unistd::getpid,
};

use scopeguard::defer;

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
pub(super) enum PmuType {
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
    Armv8,
    Unknown,
}

impl PmuType {
    pub fn detect(processor_id: usize) -> Self {
        #[cfg(target_arch = "x86_64")]
        {
            let pid_self = getpid();
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
        {
            // TODO: detection
            Self::Armv8
        }
    }

    pub fn max_skid(&self) -> u64 {
        match self {
            #[cfg(target_arch = "x86_64")]
            PmuType::Amd => 2048,
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelLakeCove | PmuType::IntelMont { .. } | PmuType::IntelOther => 1024,
            #[cfg(target_arch = "aarch64")]
            PmuType::Armv8 => todo!(),
            _ => 0,
        }
    }
}
