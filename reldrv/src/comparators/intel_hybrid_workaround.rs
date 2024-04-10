use std::sync::atomic::AtomicUsize;

use log::info;

use crate::{
    dispatcher::{Module, Subscribers},
    events::comparator::{RegisterComparator, RegisterComparsionResult},
    process::registers::{Eflags, Registers},
    statistics::{StatisticValue, StatisticsProvider},
    statistics_list,
};

pub struct IntelHybridWorkaround {
    nr_eflags_overflow_flag_mismatches: AtomicUsize,
}

impl IntelHybridWorkaround {
    pub fn new() -> Self {
        Self {
            nr_eflags_overflow_flag_mismatches: AtomicUsize::new(0),
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
        if chk_registers.eflags & Eflags::OF.bits() != ref_registers.eflags & Eflags::OF.bits() {
            info!("Overflow flag mismatch, ignoring");
            self.nr_eflags_overflow_flag_mismatches
                .fetch_add(1, std::sync::atomic::Ordering::Relaxed);

            chk_registers.eflags &= !Eflags::OF.bits();
            ref_registers.eflags &= !Eflags::OF.bits();
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
            nr_eflags_overflow_flag_mismatches = self
                .nr_eflags_overflow_flag_mismatches
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
