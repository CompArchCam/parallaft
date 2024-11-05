use std::{os::unix::process::CommandExt, process::Command};

use crate::common::{checkpoint_take, trace};
use nix::unistd::{self, ForkResult};

#[test]
fn fork() {
    trace::<()>(|| {
        match unsafe { unistd::fork().unwrap() } {
            ForkResult::Parent { .. } => {
                println!("You should not see this line");
            }
            ForkResult::Child => {
                println!("You should not see this line");
            }
        }
        unreachable!()
    })
    .unwrap_err();
}

#[test]
fn fork_in_protected_region() {
    trace::<()>(|| {
        checkpoint_take();
        unsafe { unistd::fork().unwrap() };
        unreachable!()
    })
    .unwrap_err();
}

#[test]
fn execve() {
    trace::<()>(|| {
        checkpoint_take();
        Command::new("/usr/bin/true").exec();
        unreachable!()
    })
    .unwrap_err();
}
