use std::collections::HashMap;
use std::fs;
use std::str::FromStr;

use log::info;
use parking_lot::Mutex;

use crate::dispatcher::{Dispatcher, Installable};
use crate::error::Result;
use crate::process::{ProcessLifetimeHook, ProcessLifetimeHookContext};

#[derive(Debug, Clone, Copy)]
pub enum CpuFreqGovernor {
    Ondemand,
    Userspace(u64),
}

impl FromStr for CpuFreqGovernor {
    type Err = <u64 as FromStr>::Err;

    fn from_str(s: &str) -> std::prelude::v1::Result<Self, Self::Err> {
        if s == "ondemand" {
            Ok(Self::Ondemand)
        } else {
            Ok(Self::Userspace(s.parse::<u64>()?))
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

    cpu_old_freq: Mutex<HashMap<usize, u64>>,
    cpu_old_freq_governor: Mutex<HashMap<usize, String>>,
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

            cpu_old_freq: Mutex::new(HashMap::new()),
            cpu_old_freq_governor: Mutex::new(HashMap::new()),
        }
    }

    fn get_governor_raw(cpu: usize) -> Result<String> {
        let governor = fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_governor",
            cpu
        ))?;

        Ok(governor)
    }

    fn set_governor_raw(cpu: usize, governor: &str) -> Result<()> {
        fs::write(
            format!(
                "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_governor",
                cpu
            ),
            governor,
        )?;

        info!("CPU {} governor set to {}", cpu, governor.trim_end());

        Ok(())
    }

    fn get_freq(cpu: usize) -> Result<Option<u64>> {
        let speed_str = fs::read_to_string(format!(
            "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_setspeed",
            cpu
        ))?;

        let speed = speed_str.parse::<u64>().ok();

        Ok(speed)
    }

    fn set_freq(cpu: usize, freq: u64) -> Result<()> {
        fs::write(
            format!(
                "/sys/devices/system/cpu/cpu{}/cpufreq/scaling_setspeed",
                cpu
            ),
            freq.to_string(),
        )?;

        info!("CPU {} frequency set to {} kHz", cpu, freq);

        Ok(())
    }

    fn old_params_save(&self) {
        let mut cpu_old_freq = self.cpu_old_freq.lock();
        let mut cpu_old_freq_governor = self.cpu_old_freq_governor.lock();

        for &cpu in self
            .main_cpu_set
            .into_iter()
            .chain(self.checker_cpu_set.into_iter())
            .chain(self.shell_cpu_set.into_iter())
        {
            cpu_old_freq_governor.insert(
                cpu,
                Self::get_governor_raw(cpu).expect("Unable to get old CPU freq scaling governor"),
            );

            if let Some(freq) = Self::get_freq(cpu).expect("Unable to get old CPU freq") {
                cpu_old_freq.insert(cpu, freq);
            }
        }
    }

    fn old_params_restore(&self) {
        let mut cpu_old_freq_governor = self.cpu_old_freq_governor.lock();

        for (cpu, governor) in cpu_old_freq_governor.drain() {
            Self::set_governor_raw(cpu, &governor)
                .expect("Unable to restore old CPU freq scaling governor");
        }

        let mut cpu_old_freq = self.cpu_old_freq.lock();

        for (cpu, freq) in cpu_old_freq.drain() {
            Self::set_freq(cpu, freq).expect("Unable to restore old CPU freq");
        }
    }

    fn set_governor(cpu_set: &[usize], governor: CpuFreqGovernor) {
        for &cpu in cpu_set {
            match governor {
                CpuFreqGovernor::Ondemand => {
                    Self::set_governor_raw(cpu, "ondemand")
                        .expect("Failed to set CPU freq governor");
                }
                CpuFreqGovernor::Userspace(freq) => {
                    Self::set_governor_raw(cpu, "userspace")
                        .expect("Failed to set CPU freq governor");
                    Self::set_freq(cpu, freq).expect("Failed to set CPU freq");
                }
            }
        }
    }
}

impl<'a> ProcessLifetimeHook for CpuFreqSetter<'a> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        if self.main_cpu_freq_governor.is_some()
            || self.checker_cpu_freq_governor.is_some()
            || self.shell_cpu_freq_governor.is_some()
        {
            self.old_params_save();
        }

        if let Some(g) = self.main_cpu_freq_governor {
            Self::set_governor(self.main_cpu_set, g);
        }

        if let Some(g) = self.checker_cpu_freq_governor {
            Self::set_governor(self.checker_cpu_set, g);
        }

        if let Some(g) = self.shell_cpu_freq_governor {
            Self::set_governor(self.shell_cpu_set, g);
        }

        Ok(())
    }

    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.old_params_restore();
        Ok(())
    }
}

impl<'a> Drop for CpuFreqSetter<'a> {
    fn drop(&mut self) {
        self.old_params_restore();
    }
}

impl<'a, 'b> Installable<'b> for CpuFreqSetter<'a> {
    fn install(&'b self, dispatcher: &mut Dispatcher<'b>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
