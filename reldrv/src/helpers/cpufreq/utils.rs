use std::fs;
use std::path::PathBuf;

use log::info;
use path_macro::path;

use crate::error::Result;

pub(super) mod strings {
    pub const ONDEMAND: &'static str = "ondemand";
    pub const USERSPACE: &'static str = "userspace";
    pub const SCALING_GOVERNOR: &'static str = "scaling_governor";
    pub const SCALING_SETSPEED: &'static str = "scaling_setspeed";
    pub const SCALING_MAX_FREQ: &'static str = "scaling_max_freq";
    pub const CPUINFO_MAX_FREQ: &'static str = "cpuinfo_max_freq";
    pub const CPUINFO_MIN_FREQ: &'static str = "cpuinfo_min_freq";
}

pub(super) fn get_cpufreq_dir(cpu: usize) -> PathBuf {
    format!("/sys/devices/system/cpu/cpu{}/cpufreq", cpu).into()
}

pub(super) fn read_cpufreq_item(cpu: usize, item: &str) -> Result<String> {
    Ok(fs::read_to_string(path!(get_cpufreq_dir(cpu) / item))?
        .trim_end()
        .to_string())
}

pub(super) fn write_cpufreq_item(cpu: usize, item: &str, value: &str) -> Result<()> {
    Ok(fs::write(path!(get_cpufreq_dir(cpu) / item), value)?)
}

pub(super) fn get_cpufreq_governor_raw(cpu: usize) -> Result<String> {
    read_cpufreq_item(cpu, &strings::SCALING_GOVERNOR)
}

pub(super) fn set_cpufreq_governor_raw(cpu: usize, governor: &str) -> Result<()> {
    write_cpufreq_item(cpu, &strings::SCALING_GOVERNOR, governor)?;
    info!("CPU {} governor set to {}", cpu, governor.trim_end());
    Ok(())
}

pub(super) fn get_cpufreq_speed(cpu: usize) -> Result<u64> {
    let speed_str = read_cpufreq_item(cpu, &strings::SCALING_SETSPEED)?;
    let speed = speed_str.parse::<u64>()?;
    Ok(speed)
}

pub(super) fn set_cpufreq_speed(cpu: usize, speed_khz: u64) -> Result<()> {
    write_cpufreq_item(cpu, &strings::SCALING_SETSPEED, &speed_khz.to_string())
}

pub(super) fn get_cpufreq_max_freq(cpu: usize) -> Result<u64> {
    let freq_str = read_cpufreq_item(cpu, &strings::SCALING_MAX_FREQ)?;
    let freq = freq_str.parse::<u64>()?;
    Ok(freq)
}

pub(super) fn set_cpufreq_max_freq(cpu: usize, freq_khz: u64) -> Result<()> {
    write_cpufreq_item(cpu, &strings::SCALING_MAX_FREQ, &freq_khz.to_string())
}
