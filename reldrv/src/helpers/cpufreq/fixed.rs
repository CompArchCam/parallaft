use parking_lot::Mutex;
use std::collections::HashMap;

pub use super::governor::CpuFreqGovernor;
use crate::dispatcher::{Module, Subscribers};
use crate::error::Result;
use crate::events::module_lifetime::ModuleLifetimeHook;
use crate::events::process_lifetime::HandlerContext;

pub struct FixedCpuFreqGovernorSetter<'a> {
    checker_cpu_set: &'a [usize],
    checker_cpu_freq_governor: CpuFreqGovernor,
    cpu_old_freq_governor: Mutex<HashMap<usize, CpuFreqGovernor>>,
}

impl<'a> FixedCpuFreqGovernorSetter<'a> {
    pub fn new(checker_cpu_set: &'a [usize], checker_cpu_freq_governor: CpuFreqGovernor) -> Self {
        Self {
            checker_cpu_set,
            checker_cpu_freq_governor,
            cpu_old_freq_governor: Mutex::new(HashMap::new()),
        }
    }

    fn old_params_save(&self) {
        let mut cpu_old_freq_governor = self.cpu_old_freq_governor.lock();

        for &cpu in self.checker_cpu_set {
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

impl<'a> ModuleLifetimeHook for FixedCpuFreqGovernorSetter<'a> {
    fn init<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        self.old_params_save();

        self.checker_cpu_set
            .iter()
            .try_for_each(|cpu| self.checker_cpu_freq_governor.write(*cpu))?;

        Ok(())
    }

    fn fini<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        self.old_params_restore();
        Ok(())
    }
}

impl<'a> Module for FixedCpuFreqGovernorSetter<'a> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_module_lifetime_hook(self);
    }
}
