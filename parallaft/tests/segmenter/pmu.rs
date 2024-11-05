use parallaft::{slicers::SlicerType, RelShellOptionsBuilder};

use crate::common::trace_w_options;

#[test]
fn pmu_segmentation() {
    trace_w_options::<()>(
        || {
            fn fib(a: u32) -> u32 {
                if a == 0 {
                    return 0;
                } else if a == 1 {
                    return 1;
                } else {
                    return fib(a - 1) + fib(a - 2);
                }
            }

            fib(36);

            Ok(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .exec_point_replay(true)
            .checkpoint_period(100000000)
            .slicer(SlicerType::FixedInterval)
            .main_cpu_set(vec![0])
            .checker_cpu_set(vec![0])
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}
