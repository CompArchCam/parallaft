use std::collections::HashMap;
use std::fs;
use std::path::PathBuf;
use std::str::FromStr;

use itertools::Itertools;
use log::info;
use parking_lot::Mutex;
use path_macro::path;

use crate::dispatcher::{Module, Subscribers};
use crate::error::{Error, Result};
use crate::events::module_lifetime::ModuleLifetimeHook;

#[derive(Debug, Clone)]
pub enum CpuFreqGovernor {
    Ondemand { max_freq_khz: Option<u64> },
    Userspace { speed_khz: u64 },
    Other(String),
}

mod strings {
    pub const ONDEMAND: &'static str = "ondemand";
    pub const USERSPACE: &'static str = "userspace";
    pub const SCALING_GOVERNOR: &'static str = "scaling_governor";
    pub const SCALING_SETSPEED: &'static str = "scaling_setspeed";
    pub const SCALING_MAX_FREQ: &'static str = "scaling_max_freq";
}

fn get_cpufreq_dir(cpu: usize) -> PathBuf {
    format!("/sys/devices/system/cpu/cpu{}/cpufreq", cpu).into()
}

fn read_cpufreq_item(cpu: usize, item: &str) -> Result<String> {
    Ok(fs::read_to_string(path!(get_cpufreq_dir(cpu) / item))?)
}

fn write_cpufreq_item(cpu: usize, item: &str, value: &str) -> Result<()> {
    Ok(fs::write(path!(get_cpufreq_dir(cpu) / item), value)?)
}

fn get_cpufreq_governor_raw(cpu: usize) -> Result<String> {
    read_cpufreq_item(cpu, &strings::SCALING_GOVERNOR)
}

fn set_cpufreq_governor_raw(cpu: usize, governor: &str) -> Result<()> {
    write_cpufreq_item(cpu, &strings::SCALING_GOVERNOR, governor)?;
    info!("CPU {} governor set to {}", cpu, governor.trim_end());
    Ok(())
}

fn get_cpufreq_speed(cpu: usize) -> Result<u64> {
    let speed_str = read_cpufreq_item(cpu, &strings::SCALING_SETSPEED)?;
    let speed = speed_str.parse::<u64>()?;
    Ok(speed)
}

fn set_cpufreq_speed(cpu: usize, speed_khz: u64) -> Result<()> {
    write_cpufreq_item(cpu, &strings::SCALING_SETSPEED, &speed_khz.to_string())
}

fn get_cpufreq_max_freq(cpu: usize) -> Result<u64> {
    let freq_str = read_cpufreq_item(cpu, &strings::SCALING_MAX_FREQ)?;
    let freq = freq_str.parse::<u64>()?;
    Ok(freq)
}

fn set_cpufreq_max_freq(cpu: usize, freq_khz: u64) -> Result<()> {
    write_cpufreq_item(cpu, &strings::SCALING_MAX_FREQ, &freq_khz.to_string())
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

pub struct CpuFreqSetter<'a> {
    main_cpu_set: &'a [usize],
    checker_cpu_set: &'a [usize],
    shell_cpu_set: &'a [usize],

    main_cpu_freq_governor: Option<CpuFreqGovernor>,
    checker_cpu_freq_governor: Option<CpuFreqGovernor>,
    shell_cpu_freq_governor: Option<CpuFreqGovernor>,

    cpu_old_freq_governor: Mutex<HashMap<usize, CpuFreqGovernor>>,
}

impl<'a> CpuFreqSetter<'a> {
    pub fn new(
        main_cpu_set: &'a [usize],
        checker_cpu_set: &'a [usize],
        shell_cpu_set: &'a [usize],

        main_cpu_freq_governor: Option<CpuFreqGovernor>,
        checker_cpu_freq_governor: Option<CpuFreqGovernor>,
        shell_cpu_freq_governor: Option<CpuFreqGovernor>,
    ) -> Self {
        Self {
            main_cpu_set,
            checker_cpu_set,
            shell_cpu_set,

            main_cpu_freq_governor,
            checker_cpu_freq_governor,
            shell_cpu_freq_governor,

            cpu_old_freq_governor: Mutex::new(HashMap::new()),
        }
    }

    fn old_params_save(&self) {
        let mut cpu_old_freq_governor = self.cpu_old_freq_governor.lock();

        for &cpu in self
            .main_cpu_set
            .iter()
            .chain(self.checker_cpu_set.iter())
            .chain(self.shell_cpu_set.iter())
            .unique()
        {
            cpu_old_freq_governor.insert(
                cpu,
                CpuFreqGovernor::read(cpu).expect("Unable to read CPU freq governor"),
            );
        }
    }

    fn old_params_restore(&self) {
        let mut cpu_old_freq_governor = self.cpu_old_freq_governor.lock();

        for (cpu, governor) in cpu_old_freq_governor.drain() {
            governor
                .write(cpu)
                .expect("Unable to restore CPU freq governor");
        }
    }
}

impl<'a> ModuleLifetimeHook for CpuFreqSetter<'a> {
    fn init<'s, 'scope, 'env>(
        &'s self,
        _scope: &'scope std::thread::Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
    {
        if self.main_cpu_freq_governor.is_some()
            || self.checker_cpu_freq_governor.is_some()
            || self.shell_cpu_freq_governor.is_some()
        {
            self.old_params_save();
        }

        if let Some(g) = &self.main_cpu_freq_governor {
            self.main_cpu_set.iter().try_for_each(|cpu| g.write(*cpu))?;
        }

        if let Some(g) = &self.checker_cpu_freq_governor {
            self.checker_cpu_set
                .iter()
                .try_for_each(|cpu| g.write(*cpu))?;
        }

        if let Some(g) = &self.shell_cpu_freq_governor {
            self.shell_cpu_set
                .iter()
                .try_for_each(|cpu| g.write(*cpu))?;
        }

        Ok(())
    }

    fn fini<'s, 'scope, 'env>(
        &'s self,
        _scope: &'scope std::thread::Scope<'scope, 'env>,
    ) -> Result<()>
    where
        's: 'scope,
    {
        self.old_params_restore();
        Ok(())
    }
}

impl<'a> Module for CpuFreqSetter<'a> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_module_lifetime_hook(self);
    }
}
