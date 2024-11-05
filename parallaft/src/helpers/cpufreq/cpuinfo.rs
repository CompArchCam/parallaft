use super::utils::{read_cpufreq_item, strings};

use crate::error::Result;

pub struct CpuInfo {
    pub freq_max_khz: u64,
    pub freq_min_khz: u64,
}

impl CpuInfo {
    pub fn get(cpu: usize) -> Result<Self> {
        let max_freq_str = read_cpufreq_item(cpu, &strings::CPUINFO_MAX_FREQ)?;
        let min_freq_str = read_cpufreq_item(cpu, &strings::CPUINFO_MIN_FREQ)?;

        let max_freq = max_freq_str.parse::<u64>()?;
        let min_freq = min_freq_str.parse::<u64>()?;

        Ok(Self {
            freq_max_khz: max_freq,
            freq_min_khz: min_freq,
        })
    }
}
