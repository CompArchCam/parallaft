use parallaft::{
    signal_handlers::mrs::mrs, types::segment_record::saved_trap_event::SystemReg,
    RelShellOptionsBuilder,
};

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

#[test]

fn test_mrs() {
    trace_w_options(
        || {
            checkpoint_take();
            unsafe {
                mrs(SystemReg::CTR_EL0);
                mrs(SystemReg::DCZID_EL0);
            }
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}
