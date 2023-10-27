use crate::common::{checkpoint_fini, checkpoint_take, setup, trace};
use nix::unistd;
use serial_test::serial;

#[test]
#[serial]
fn read_write() {
    setup();
    assert_eq!(
        trace(|| {
            let (rx, tx) = unistd::pipe().unwrap();

            checkpoint_take();

            let data = [0, 1, 2, 3, 4, 5, 6, 7];
            unistd::write(tx, &data).unwrap();

            let mut buf = [0u8; 4];
            unistd::read(rx, &mut buf).unwrap();
            assert_eq!(buf, data[..4]);
            unistd::read(rx, &mut buf).unwrap();
            assert_eq!(buf, data[4..]);

            unistd::close(rx).unwrap();
            unistd::close(tx).unwrap();

            checkpoint_fini();
            0
        }),
        0
    )
}
