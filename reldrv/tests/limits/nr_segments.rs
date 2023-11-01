use crate::common::{checkpoint_fini, checkpoint_take, setup, trace_with_options, RelShellOptions};
use nix::libc;
use reldrv::RunnerFlags;
use serial_test::serial;

#[test]
#[serial]
fn limit_1() {
    setup();

    let mut options = RelShellOptions::default();

    options.max_nr_live_segments = 1;
    options.runner_flags.insert(RunnerFlags::DONT_TRAP_CPUID);
    options.runner_flags.insert(RunnerFlags::DONT_TRAP_RDTSC);

    assert_eq!(
        trace_with_options(
            || {
                for _ in 0..20 {
                    checkpoint_take();
                }
                checkpoint_fini();
                0
            },
            options
        ),
        0
    );
}

#[test]
#[serial]
fn limit_8_getpid_loop() {
    setup();

    let mut options = RelShellOptions::default();

    options.max_nr_live_segments = 8;
    options.runner_flags.insert(RunnerFlags::DONT_TRAP_CPUID);
    options.runner_flags.insert(RunnerFlags::DONT_TRAP_RDTSC);

    assert_eq!(
        trace_with_options(
            || {
                for _ in 0..2000 {
                    checkpoint_take();
                    unsafe { libc::getpid() };
                }
                checkpoint_fini();
                0
            },
            options
        ),
        0
    );
}
