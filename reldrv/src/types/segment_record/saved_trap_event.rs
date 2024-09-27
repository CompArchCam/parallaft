#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

use cfg_if::cfg_if;

#[derive(Debug, Clone, Copy)]
pub enum SavedTrapEvent {
    #[cfg(target_arch = "x86_64")]
    Rdtsc(u64),

    #[cfg(target_arch = "x86_64")]
    Rdtscp(u64, u32), // tsc, aux

    #[cfg(target_arch = "x86_64")]
    Cpuid(u32, u32, CpuidResult), // leaf, subleaf, result

    #[cfg(target_arch = "aarch64")]
    Mrs(MrsInstruction, u64), // insn, value
}

cfg_if! {
    if #[cfg(target_arch = "aarch64")] {
        use std::fmt::{Display, Formatter};
        use crate::process::registers::Register;

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

        #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
        pub struct MrsInstruction {
            pub rt: Register,
            pub sys_reg: SystemReg,
        }

        impl Display for MrsInstruction {
            fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
                write!(f, "mrs {}, {:?}", self.rt, self.sys_reg)
            }
        }
    }
}
