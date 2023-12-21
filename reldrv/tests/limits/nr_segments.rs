use crate::common::{checkpoint_fini, checkpoint_take, setup, trace_with_options, RelShellOptions};
use nix::libc;
use serial_test::serial;

#[cfg(target_arch = "x86_64")]
use reldrv::RunnerFlags;

#[test]
#[serial]
fn limit_1() {
    setup();

    let mut options = RelShellOptions::default();

    options.max_nr_live_segments = 1;

    #[cfg(target_arch = "x86_64")]
    options.runner_flags.insert(RunnerFlags::DONT_TRAP_CPUID);

    #[cfg(target_arch = "x86_64")]
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

    #[cfg(target_arch = "x86_64")]
    options.runner_flags.insert(RunnerFlags::DONT_TRAP_CPUID);

    #[cfg(target_arch = "x86_64")]
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
