use std::str::FromStr;

use crate::error::{Error, Result};

use super::utils::{
    get_cpufreq_governor_raw, get_cpufreq_max_freq, get_cpufreq_speed, set_cpufreq_governor_raw,
    set_cpufreq_max_freq, set_cpufreq_speed, strings,
};

#[derive(Debug, Clone)]
pub enum CpuFreqGovernor {
    Ondemand { max_freq_khz: Option<u64> },
    Userspace { speed_khz: u64 },
    Other(String),
}

impl CpuFreqGovernor {
    pub fn read(cpu: usize) -> Result<Self> {
        let governor_raw = get_cpufreq_governor_raw(cpu)?;

        Ok(match governor_raw.as_str() {
            strings::ONDEMAND => Self::Ondemand {
                max_freq_khz: Some(get_cpufreq_max_freq(cpu)?),
            },
            strings::USERSPACE => Self::Userspace {
                speed_khz: get_cpufreq_speed(cpu)?,
            },
            other @ _ => Self::Other(other.to_string()),
        })
    }

    pub fn write(&self, cpu: usize) -> Result<()> {
        match self {
            CpuFreqGovernor::Ondemand { max_freq_khz } => {
                set_cpufreq_governor_raw(cpu, &strings::ONDEMAND)?;
                if let Some(max_freq_khz) = max_freq_khz {
                    set_cpufreq_max_freq(cpu, *max_freq_khz)?;
                }
            }
            CpuFreqGovernor::Userspace { speed_khz } => {
                set_cpufreq_governor_raw(cpu, &strings::USERSPACE)?;
                set_cpufreq_speed(cpu, *speed_khz)?;
            }
            CpuFreqGovernor::Other(governor_raw) => {
                set_cpufreq_governor_raw(cpu, governor_raw)?;
            }
        }

        Ok(())
    }
}

impl FromStr for CpuFreqGovernor {
    type Err = Error;

    fn from_str(s: &str) -> std::result::Result<Self, Self::Err> {
        let (governor, param_value) = s
            .split_once(":")
            .map(|x| (x.0, Some(x.1)))
            .unwrap_or((s, None));

        match (governor, param_value) {
            (strings::ONDEMAND, None) => Ok(Self::Ondemand { max_freq_khz: None }),
            (strings::ONDEMAND, Some(param_value)) => Ok(Self::Ondemand {
                max_freq_khz: Some(param_value.parse::<u64>()?),
            }),
            (strings::USERSPACE, Some(param_value)) => Ok(Self::Userspace {
                speed_khz: param_value.parse::<u64>()?,
            }),
            _ => Err(Error::NotSupported(
                "Unsupported CPU freq governor".to_string(),
            )),
        }
    }
}
