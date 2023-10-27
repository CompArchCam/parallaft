use std::{os::unix::process::CommandExt, process::Command};

use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};
use nix::unistd::{self, ForkResult};
use serial_test::serial;

#[test]
#[serial]
#[should_panic]
fn fork() {
    setup();
    trace(|| {
        match unsafe { unistd::fork().unwrap() } {
            ForkResult::Parent { .. } => {
                println!("You should not see this line");
            }
            ForkResult::Child => {
                println!("You should not see this line");
            }
        };
        0
    });
}

#[test]
#[serial]
#[should_panic]
fn fork_in_protected_region() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();

            unsafe { unistd::fork().unwrap() };

            checkpoint_fini();
            0
        }),
        0
    )
}

#[test]
#[serial]
#[should_panic]
fn execve() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();

            Command::new("/usr/bin/true").exec();

            checkpoint_fini();
            0
        }),
        0
    )
}
