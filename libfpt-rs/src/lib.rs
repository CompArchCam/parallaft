mod ioctl;

use bitflags::bitflags;
use ioctl::{FptAttachRequest, FptReadFaultRequest};
use nix::fcntl::OFlag;
use nix::libc;
use nix::sys::mman::{MapFlags, ProtFlags};
use nix::sys::stat::Mode;
use nix::unistd::{self, Pid};
use nix::{fcntl, Result};
use std::mem::MaybeUninit;
use std::num::NonZeroUsize;
use std::os::fd::{AsFd, AsRawFd, BorrowedFd, RawFd};

pub struct FptRecord {
    addr: *const usize,
    data_length: usize,
    map_length: usize,
}

impl FptRecord {
    pub(crate) fn new(fd: &FptFd) -> Result<FptRecord> {
        let sz = fd.get_buffer_size()? * std::mem::size_of::<usize>();
        let data_len = fd.get_count()?;

        let addr = unsafe {
            nix::sys::mman::mmap(
                None,
                NonZeroUsize::new_unchecked(sz),
                ProtFlags::PROT_READ,
                MapFlags::MAP_PRIVATE,
                Some(fd),
                0,
            )?
        };

        Ok(Self {
            addr: addr as _,
            data_length: data_len,
            map_length: sz,
        })
    }
}

impl AsRef<[usize]> for FptRecord {
    fn as_ref(&self) -> &[usize] {
        unsafe { std::slice::from_raw_parts(self.addr, self.data_length) }
    }
}

impl Drop for FptRecord {
    fn drop(&mut self) {
        unsafe { nix::sys::mman::munmap(self.addr as *mut _, self.map_length).ok() };
    }
}

pub struct FptFd {
    fd: RawFd,
}

bitflags! {
    pub struct FptFlags: libc::c_int {
        const EXCLUDE_NON_WRITABLE_VMA = 0b0001;
        const SIGTRAP_FULL = 0b0010;
        const SIGTRAP_WATERMARK = 0b0100;
        const SIGTRAP_WATERMARK_USER = 0b1000;
        const ALLOW_REALLOC = 0b10000;
    }
}

pub const TRAP_FPT_FULL: libc::c_int = 0xff77;
pub const TRAP_FPT_WATERMARK: libc::c_int = 0xff78;
pub const TRAP_FPT_WATERMARK_USER: libc::c_int = 0xff79;
pub const FPT_DEV: &'static str = "/dev/fpt";

impl FptFd {
    pub fn new(
        pid: Pid,
        buffer_size: usize,
        flags: FptFlags,
        watermark: Option<usize>,
    ) -> Result<Self> {
        let fd = fcntl::open(FPT_DEV, OFlag::O_RDONLY, Mode::empty())?;

        unsafe {
            ioctl::fptioc_attach_process(
                fd,
                &FptAttachRequest {
                    pid: pid.as_raw(),
                    buffer_size: buffer_size as _,
                    flags: flags.bits(),
                    watermark: watermark.unwrap_or(0),
                },
            )
        }?;

        Ok(Self { fd })
    }

    pub fn enable(&mut self) -> Result<()> {
        unsafe { ioctl::fptioc_enable(self.fd).map(|_| ()) }
    }

    pub fn disable(&mut self) -> Result<()> {
        unsafe { ioctl::fptioc_disable(self.fd).map(|_| ()) }
    }

    pub fn clear_fault(&mut self) -> Result<()> {
        unsafe { ioctl::fptioc_clear_fault(self.fd).map(|_| ()) }
    }

    pub fn read_fault(&self, buf: &mut [usize], offset: usize) -> Result<usize> {
        unsafe {
            ioctl::fptioc_read_fault(
                self.fd,
                &FptReadFaultRequest {
                    buffer: buf.as_mut_ptr() as *mut usize,
                    size: buf.len(),
                    offset: offset as _,
                },
            )
            .map(|x| x as _)
        }
    }

    pub fn get_count(&self) -> Result<usize> {
        let mut count = MaybeUninit::<libc::size_t>::uninit();
        unsafe {
            ioctl::fptioc_get_count(self.fd, count.as_mut_ptr())?;
            Ok(count.assume_init() as _)
        }
    }

    pub fn get_lost_count(&self) -> Result<usize> {
        let mut count = MaybeUninit::<libc::size_t>::uninit();
        unsafe {
            ioctl::fptioc_get_lost_count(self.fd, count.as_mut_ptr())?;
            Ok(count.assume_init() as _)
        }
    }

    pub fn get_buffer_size(&self) -> Result<usize> {
        let mut sz = MaybeUninit::<libc::size_t>::uninit();
        unsafe {
            ioctl::fptioc_get_buffer_size(self.fd, sz.as_mut_ptr())?;
            Ok(sz.assume_init() as _)
        }
    }

    pub fn new_buffer(&self) -> Result<()> {
        unsafe { ioctl::fptioc_new_buffer(self.fd).map(|_| ()) }
    }

    pub fn take_record(&self) -> Result<FptRecord> {
        let record = FptRecord::new(self)?;
        self.new_buffer()?;
        Ok(record)
    }
}

impl AsFd for FptFd {
    fn as_fd(&self) -> BorrowedFd<'_> {
        unsafe { BorrowedFd::borrow_raw(self.fd) }
    }
}

impl AsRawFd for FptFd {
    fn as_raw_fd(&self) -> RawFd {
        self.fd
    }
}

impl Drop for FptFd {
    fn drop(&mut self) {
        unistd::close(self.fd).ok();
    }
}

#[cfg(test)]
mod tests {
    use std::os::fd::OwnedFd;

    use nix::{
        sys::{
            signal::{
                kill, raise,
                Signal::{SIGCONT, SIGSTOP},
            },
            wait::{waitpid, WaitPidFlag, WaitStatus},
        },
        unistd::{fork, sysconf, SysconfVar},
    };

    use lazy_static::lazy_static;

    lazy_static! {
        static ref PAGE_SIZE: usize = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;
    }

    use super::*;

    fn subprocess(f: impl FnOnce() -> ()) -> Pid {
        match unsafe { fork().unwrap() } {
            unistd::ForkResult::Parent { child } => child,
            unistd::ForkResult::Child => {
                raise(SIGSTOP).unwrap();

                f();

                std::process::exit(0);
            }
        }
    }

    fn wait_for_sigstop(pid: Pid) {
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WSTOPPED)).unwrap(),
            WaitStatus::Stopped(pid, SIGSTOP)
        );
    }

    fn continue_subprocess(pid: Pid) {
        kill(pid, SIGCONT).unwrap();
    }

    fn wait_for_finish(pid: Pid) {
        loop {
            let result = waitpid(pid, None).unwrap();

            if matches!(result, WaitStatus::Exited(_, _)) {
                break;
            }
        }
    }

    fn get_shared_pointer<T>() -> Result<*mut *const T> {
        unsafe {
            nix::sys::mman::mmap::<OwnedFd>(
                None,
                NonZeroUsize::new_unchecked(*PAGE_SIZE),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_ANONYMOUS | MapFlags::MAP_SHARED,
                None,
                0,
            )
            .map(|p| p as *mut *const T)
        }
    }

    fn put_shared_pointer<T>(ptr: *mut *const T) -> Result<()> {
        unsafe { nix::sys::mman::munmap(ptr as _, *PAGE_SIZE).map(|_| ()) }
    }

    fn get_num_pages_in_range(list: &[usize], addr: usize, size: usize) -> usize {
        list.into_iter()
            .filter(|&&a| (a >= addr & (!(*PAGE_SIZE - 1))) && (a <= (addr + size)))
            .count()
    }

    #[test]
    fn test_open_close_fpt() {
        let pid = subprocess(|| {});
        let fd = FptFd::new(pid, 1024, FptFlags::empty(), None).unwrap();
        wait_for_sigstop(pid);
        continue_subprocess(pid);
        wait_for_finish(pid);

        drop(fd);
    }

    #[test]
    fn test_read_fault() {
        let cnt = 1024;

        let vec_addr_p = get_shared_pointer().unwrap();

        let pid = subprocess(|| {
            let mut v = vec![0u8; *PAGE_SIZE * cnt];
            unsafe { *vec_addr_p = v.as_ptr() };

            v.fill(42);
        });

        let mut fd = FptFd::new(pid, 2048, FptFlags::empty(), None).unwrap();

        wait_for_sigstop(pid);
        fd.enable().unwrap();
        continue_subprocess(pid);
        wait_for_finish(pid);
        fd.disable().unwrap();

        let mut buf = vec![0 as usize; 4096];
        let s = fd.read_fault(&mut buf, 0).unwrap();

        assert!(s >= cnt);

        let num_dirty_pages_in_vec =
            get_num_pages_in_range(&buf, unsafe { *vec_addr_p } as _, cnt * *PAGE_SIZE);
        assert!(num_dirty_pages_in_vec >= cnt);
        put_shared_pointer(vec_addr_p).unwrap();
    }

    #[test]
    fn test_take_record_single() {
        let cnt = 1024;
        let vec_addr_p = get_shared_pointer().unwrap();

        let pid = subprocess(|| {
            let mut v = vec![0u8; *PAGE_SIZE * cnt];
            unsafe { *vec_addr_p = v.as_ptr() };

            v.fill(42);
        });

        let mut fd = FptFd::new(pid, 2048, FptFlags::empty(), None).unwrap();

        wait_for_sigstop(pid);
        fd.enable().unwrap();
        continue_subprocess(pid);
        wait_for_finish(pid);
        fd.disable().unwrap();

        let record = fd.take_record().unwrap();

        let buf = record.as_ref();
        assert!(buf.len() >= cnt);

        let num_dirty_pages_in_vec =
            get_num_pages_in_range(&buf, unsafe { *vec_addr_p } as _, cnt * *PAGE_SIZE);
        assert!(num_dirty_pages_in_vec >= cnt);
        put_shared_pointer(vec_addr_p).unwrap();
    }

    #[test]
    fn test_take_record_multiple() {
        let cnt = 1024;
        let vec1_addr_p = get_shared_pointer().unwrap();
        let vec2_addr_p = get_shared_pointer().unwrap();

        let pid = subprocess(|| {
            let mut v1 = vec![0u8; *PAGE_SIZE * cnt];
            unsafe { *vec1_addr_p = v1.as_ptr() };
            v1.fill(42);

            raise(SIGSTOP).unwrap();

            let mut v2 = vec![0u8; *PAGE_SIZE * cnt];
            unsafe { *vec2_addr_p = v2.as_ptr() };
            v2.fill(42);
        });

        let mut fd = FptFd::new(pid, 2048, FptFlags::empty(), None).unwrap();

        wait_for_sigstop(pid);
        fd.enable().unwrap();
        continue_subprocess(pid);
        wait_for_sigstop(pid);
        fd.disable().unwrap();
        let record1 = fd.take_record().unwrap();

        fd.enable().unwrap();
        continue_subprocess(pid);
        wait_for_finish(pid);
        fd.disable().unwrap();
        let record2 = fd.take_record().unwrap();

        let buf1 = record1.as_ref();
        // dbg!(unsafe { std::mem::transmute::<_, &[*const u8]>(buf1) });

        assert!(buf1.len() >= cnt);
        assert!(buf1.len() < cnt * 2);
        let num_dirty_pages_in_vec1 =
            get_num_pages_in_range(&buf1, unsafe { *vec1_addr_p } as _, cnt * *PAGE_SIZE);
        assert!(num_dirty_pages_in_vec1 >= cnt);

        let buf2 = record2.as_ref();
        // dbg!(unsafe { std::mem::transmute::<_, &[*const u8]>(buf2) });
        assert!(buf2.len() >= cnt);
        assert!(buf2.len() < cnt * 2);
        let num_dirty_pages_in_vec2 =
            get_num_pages_in_range(&buf2, unsafe { *vec2_addr_p } as _, cnt * *PAGE_SIZE);
        assert!(num_dirty_pages_in_vec2 >= cnt);

        put_shared_pointer(vec1_addr_p).unwrap();
        put_shared_pointer(vec2_addr_p).unwrap();
    }

    #[test]
    fn test_realloc() {
        let cnt = 4096;
        let vec_addr_p = get_shared_pointer().unwrap();

        let pid = subprocess(|| {
            let mut v = vec![0u8; *PAGE_SIZE * cnt];
            unsafe { *vec_addr_p = v.as_ptr() };

            v.fill(42);
        });

        let mut fd = FptFd::new(pid, 512, FptFlags::ALLOW_REALLOC, None).unwrap();

        wait_for_sigstop(pid);
        fd.enable().unwrap();
        continue_subprocess(pid);
        wait_for_finish(pid);
        fd.disable().unwrap();

        let lost_count = fd.get_lost_count().unwrap();
        assert_eq!(lost_count, 0);

        let total_count = fd.get_count().unwrap();
        assert!(total_count >= cnt);

        let record = fd.take_record().unwrap();

        let buf = record.as_ref();
        assert!(buf.len() >= cnt);

        let num_dirty_pages_in_vec =
            get_num_pages_in_range(&buf, unsafe { *vec_addr_p } as _, cnt * *PAGE_SIZE);
        assert!(num_dirty_pages_in_vec >= cnt);
        put_shared_pointer(vec_addr_p).unwrap();
    }

    // TODO: test SIGTRAP
}
