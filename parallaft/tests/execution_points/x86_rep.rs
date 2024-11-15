use std::{arch::asm, convert::Infallible};

use parallaft::{
    slicers::{ReferenceType, SlicerType},
    RelShellOptionsBuilder,
};

use crate::common::trace_w_options;

#[ignore = "does not work yet"]
#[test]
fn test_exec_point_rr_for_rep_movsb() {
    trace_w_options(
        || {
            let src: Vec<u32> = Vec::from_iter(0..16384);
            let mut dst: Vec<u32> = vec![0; 16384];

            for _ in 0..1024 * 1024 {
                unsafe {
                    asm!(
                        "rep movsb",
                        in("rcx") src.len() * size_of::<u32>(),
                        in("rsi") src.as_ptr(),
                        in("rdi") dst.as_mut_ptr(),
                        options(nostack, preserves_flags)
                    )
                };
            }

            Ok::<_, Infallible>(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .exec_point_replay(true)
            .main_cpu_set(vec![0])
            .checker_cpu_set(vec![1, 2])
            .slicer(SlicerType::FixedInterval)
            .checkpoint_period(100000)
            .fixed_interval_slicer_reference_type(ReferenceType::Cycles)
            .no_aslr(true)
            .core_dump(true)
            .core_dump_dir(".".into())
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect();
}
