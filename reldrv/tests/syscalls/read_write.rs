use crate::common::{checkpoint_fini, checkpoint_take, trace};
use nix::unistd;

#[test]
fn read_write() {
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
        Ok::<_, ()>(())
    })
    .expect()
}
