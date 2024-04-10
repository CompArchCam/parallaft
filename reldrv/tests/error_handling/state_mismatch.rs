use reldrv::{dispatcher::Module, events::comparator::RegisterComparator, RelShellOptionsBuilder};

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

struct AlwaysFailingRegisterComparator;

impl RegisterComparator for AlwaysFailingRegisterComparator {
    fn compare_registers(
        &self,
        _chk_registers: &mut reldrv::process::registers::Registers,
        _ref_registers: &mut reldrv::process::registers::Registers,
    ) -> reldrv::error::Result<reldrv::events::comparator::RegisterComparsionResult> {
        Ok(reldrv::events::comparator::RegisterComparsionResult::Fail)
    }
}

impl Module for AlwaysFailingRegisterComparator {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut reldrv::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_register_comparator(self)
    }
}

#[test]
fn register_comparsion_failure_single() {
    trace_w_options(
        || {
            checkpoint_take();
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .extra_modules(vec![Box::new(AlwaysFailingRegisterComparator)])
            .build()
            .unwrap(),
    )
    .expect_state_mismatch()
}

#[test]
fn register_comparsion_failure_double() {
    trace_w_options(
        || {
            checkpoint_take();
            checkpoint_take();
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .extra_modules(vec![Box::new(AlwaysFailingRegisterComparator)])
            .build()
            .unwrap(),
    )
    .expect_state_mismatch()
}
