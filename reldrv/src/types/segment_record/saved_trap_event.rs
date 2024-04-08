#[cfg(target_arch = "x86_64")]
use std::arch::x86_64::CpuidResult;

#[derive(Debug, Clone, Copy)]
pub enum SavedTrapEvent {
    #[cfg(target_arch = "x86_64")]
    Rdtsc(u64),

    #[cfg(target_arch = "x86_64")]
    Rdtscp(u64, u32), // tsc, aux

    #[cfg(target_arch = "x86_64")]
    Cpuid(u32, u32, CpuidResult), // leaf, subleaf, result
}
