use std::{fs::File, io::IoSliceMut};

use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};
use nix::sys::uio;
use serial_test::serial;

#[test]
#[serial]
#[should_panic]
fn preadv() {
    setup();
    assert_eq!(
        trace(|| {
            checkpoint_take();
            let fd = File::open("/dev/zero").unwrap();
            let mut buf = [0u8; 16];
            uio::preadv(fd, &mut [IoSliceMut::new(&mut buf)], 0).unwrap();
            checkpoint_fini();
            0
        }),
        0
    )
}
