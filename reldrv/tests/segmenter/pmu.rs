use reldrv::RelShellOptionsBuilder;

use crate::common::trace_w_options;

#[test]
fn pmu_segmentation() {
    trace_w_options::<()>(
        || {
            let mut v = Vec::new();
            for i in 0..10000000 {
                v.push(i);
            }

            Ok(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .pmu_segmentation(true)
            .checkpoint_period(10000000)
            .main_cpu_set(vec![0])
            .checker_cpu_set(vec![0])
            .build()
            .unwrap(),
    )
    .expect()
}
