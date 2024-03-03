use std::{
    ffi::CString,
    fs::File,
    num::NonZeroUsize,
    os::fd::{AsRawFd, OwnedFd},
    slice,
};

use crate::common::{checkpoint_fini, checkpoint_take, trace};
use nix::{
    sys::{
        memfd::{memfd_create, MemFdCreateFlag},
        mman,
    },
    unistd,
};

#[test]
fn mmap_anon() {
    trace(|| {
        checkpoint_take();

        const LEN: usize = 4096 * 4;

        let addr = unsafe {
            mman::mmap::<OwnedFd>(
                None,
                NonZeroUsize::new(LEN).unwrap(),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                None,
                0,
            )
            .unwrap()
        };

        let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

        // ensure we can read and write the mremap-ped memory
        arr.fill(42);
        assert!(arr.iter().all(|&x| x == 42));

        unsafe { mman::munmap(addr, LEN).unwrap() };

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn mmap_fd_read_dev_zero() {
    trace(|| {
        let file = File::open("/dev/zero").unwrap();
        const LEN: usize = 4096 * 4;

        checkpoint_take();

        let addr = unsafe {
            mman::mmap(
                None,
                NonZeroUsize::new(LEN).unwrap(),
                mman::ProtFlags::PROT_READ,
                mman::MapFlags::MAP_PRIVATE,
                Some(&file),
                0,
            )
            .unwrap()
        };

        let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };
        assert!(arr.iter().all(|&x| x == 0));

        unsafe { mman::munmap(addr, LEN).unwrap() };

        drop(file);

        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn mmap_fd_read_memfd() {
    trace(|| {
        let fd = memfd_create(
            &CString::new("reldrv-test").unwrap(),
            MemFdCreateFlag::empty(),
        )
        .unwrap();

        const LEN: usize = 4096 * 4;
        unistd::write(fd.as_raw_fd(), &[42u8; LEN]).unwrap();

        checkpoint_take();

        let addr = unsafe {
            mman::mmap(
                None,
                NonZeroUsize::new(LEN).unwrap(),
                mman::ProtFlags::PROT_READ,
                mman::MapFlags::MAP_PRIVATE,
                Some(&fd),
                0,
            )
            .unwrap()
        };

        let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

        assert!(arr.iter().all(|&x| x == 42));

        unsafe { mman::munmap(addr, LEN).unwrap() };

        drop(fd);

        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn mmap_fd_write_shared_memfd() {
    // TODO: incomplete implementation: changes to writable and shared mmap regions do not propagate to fds
    trace(|| {
        let fd = memfd_create(
            &CString::new("reldrv-test").unwrap(),
            MemFdCreateFlag::empty(),
        )
        .unwrap();

        const LEN: usize = 4096 * 4;
        unistd::write(fd.as_raw_fd(), &[0u8; LEN]).unwrap();

        checkpoint_take();

        let addr = unsafe {
            mman::mmap(
                None,
                NonZeroUsize::new(LEN).unwrap(),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_SHARED,
                Some(&fd),
                0,
            )
            .unwrap()
        };

        let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

        assert!(arr.iter().all(|&x| x == 0));

        arr.fill(42);

        assert!(arr.iter().all(|&x| x == 42));

        unsafe { mman::munmap(addr, LEN).unwrap() };

        drop(fd);

        Ok::<_, ()>(())
    })
    .expect_state_mismatch() // shared mmap not handled yet
}

// TODO: test MAP_SHARED-to-MAP_PRIVATE transformation

#[test]
fn mremap_maymove() {
    trace(|| {
        checkpoint_take();

        const LEN: usize = 4096 * 4;
        const NEW_LEN: usize = 4096 * 8;

        let addr = unsafe {
            mman::mmap::<OwnedFd>(
                None,
                NonZeroUsize::new(LEN).unwrap(),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                None,
                0,
            )
            .unwrap()
        };

        let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

        // ensure we can write the mmap-ped memory
        arr.fill(42);

        let addr_new = unsafe {
            mman::mremap(addr, LEN, NEW_LEN, mman::MRemapFlags::MREMAP_MAYMOVE, None).unwrap()
        };

        let arr_new = unsafe { slice::from_raw_parts_mut(addr_new as *mut u8, NEW_LEN) };

        // ensure we can read and write the mmap-ped memory
        arr_new.fill(84);
        arr_new.iter().all(|&x| x == 84);

        unsafe { mman::munmap(addr, LEN).unwrap() };

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}

#[test]
fn mremap_may_not_move() {
    trace(|| {
        checkpoint_take();

        const LEN: usize = 4096 * 4;
        const NEW_LEN: usize = 4096 * 2;

        let addr = unsafe {
            mman::mmap::<OwnedFd>(
                None,
                NonZeroUsize::new(LEN).unwrap(),
                mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                None,
                0,
            )
            .unwrap()
        };

        let arr = unsafe { slice::from_raw_parts_mut(addr as *mut u8, LEN) };

        // ensure we can write the mmap-ped memory
        arr.fill(42);

        let addr_new =
            unsafe { mman::mremap(addr, LEN, NEW_LEN, mman::MRemapFlags::empty(), None).unwrap() };

        let arr_new = unsafe { slice::from_raw_parts_mut(addr_new as *mut u8, NEW_LEN) };

        // ensure we can read and write the mmap-ped memory
        arr_new.fill(84);
        arr_new.iter().all(|&x| x == 84);

        unsafe { mman::munmap(addr, NEW_LEN).unwrap() };

        checkpoint_fini();
        Ok::<_, ()>(())
    })
    .expect()
}
