#[cfg(target_arch = "x86_64")]
mod cpuid;

#[cfg(target_arch = "x86_64")]
mod rdtsc;

#[cfg(target_arch = "aarch64")]
mod mrs;
