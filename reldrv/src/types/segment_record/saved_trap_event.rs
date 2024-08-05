#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

use cfg_if::cfg_if;

use crate::process::registers::Register;

#[derive(Debug, Clone, Copy)]
pub enum SavedTrapEvent {
    #[cfg(target_arch = "x86_64")]
    Rdtsc(u64),

    #[cfg(target_arch = "x86_64")]
    Rdtscp(u64, u32), // tsc, aux

    #[cfg(target_arch = "x86_64")]
    Cpuid(u32, u32, CpuidResult), // leaf, subleaf, result

    #[cfg(target_arch = "aarch64")]
    Mrs(Register, SystemReg, u64), // Rt, SystemReg, value
}

cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        #[allow(non_camel_case_types)]
        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub enum SystemReg {
            MIDR_EL1,
            CTR_EL0,
            DCZID_EL0,
        }

        impl SystemReg {
            pub fn from_raw(value: u16) -> Option<Self> {
                match value {
                    0xc000 => Some(Self::MIDR_EL1),
                    0xd801 => Some(Self::CTR_EL0),
                    0xd807 => Some(Self::DCZID_EL0),
                    _ => None,
                }
            }
        }
    }
}
