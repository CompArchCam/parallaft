use std::sync::atomic::AtomicUsize;

use log::info;

use crate::{
    dispatcher::{Module, Subscribers},
    events::comparator::{RegisterComparator, RegisterComparsionResult},
    process::registers::Registers,
    statistics::{StatisticValue, StatisticsProvider},
    statistics_list,
};

pub struct IntelHybridWorkaround {
    nr_eflags_mismatches: AtomicUsize,
}

impl Default for IntelHybridWorkaround {
    fn default() -> Self {
        Self::new()
    }
}

impl IntelHybridWorkaround {
    pub fn new() -> Self {
        Self {
            nr_eflags_mismatches: AtomicUsize::new(0),
        }
    }
}

impl RegisterComparator for IntelHybridWorkaround {
    fn compare_registers(
        &self,
        chk_registers: &mut Registers,
        ref_registers: &mut Registers,
    ) -> crate::error::Result<RegisterComparsionResult> {
        // Shift instructions may give different OF
        if chk_registers.eflags != ref_registers.eflags {
            info!(
                "Eflags mismatch, ignoring: {:#018x} != {:#018x}",
                chk_registers.eflags, ref_registers.eflags
            );
            self.nr_eflags_mismatches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            chk_registers.eflags = ref_registers.eflags;
        }

        Ok(RegisterComparsionResult::NoResult)
    }
}

impl StatisticsProvider for IntelHybridWorkaround {
    fn class_name(&self) -> &'static str {
        "intel_hybrid_workaround"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        statistics_list!(
            nr_eflags_mismatches = self
                .nr_eflags_mismatches
                .load(std::sync::atomic::Ordering::Relaxed)
        )
    }
}

impl Module for IntelHybridWorkaround {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_stats_providers(self);
        subs.install_register_comparator(self);
    }
}
