use std::{fs::File, io::IoSliceMut};

use crate::common::{checkpoint_take, trace};
use nix::sys::uio;

#[test]
fn preadv() {
    trace::<()>(|| {
        checkpoint_take();
        let fd = File::open("/dev/zero").unwrap();
        let mut buf = [0u8; 16];
        uio::preadv(fd, &mut [IoSliceMut::new(&mut buf)], 0).unwrap();
        unreachable!();
    })
    .expect_crash()
}
