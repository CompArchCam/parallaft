mod ioctl;

use bitflags::bitflags;
use ioctl::{FptAttachRequest, FptReadFaultRequest};
use nix::fcntl::OFlag;
use nix::libc;
use nix::sys::stat::Mode;
use nix::unistd::{self, Pid};
use nix::{fcntl, Result};
use std::os::fd::RawFd;

pub struct FptFd {
    fd: RawFd,
}

bitflags! {
    #[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
    pub struct FptFlags: libc::c_int {
        const ExcludeNonWritableVMA = 0b0001;
        const SigTrapFull = 0b0010;
        const SigTrapWatermark = 0b0100;
        const SigTrapWatermarkUser = 0b1000;
    }
}

impl FptFd {
    pub fn new(
        pid: Pid,
        buffer_size: usize,
        flags: FptFlags,
        watermark: Option<usize>,
    ) -> Result<Self> {
        let fd = fcntl::open("/dev/fpt", OFlag::O_RDONLY, Mode::empty())?;

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

    pub fn read_fault(&mut self, buf: &mut [*const u8], offset: usize) -> Result<usize> {
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
}

impl Drop for FptFd {
    fn drop(&mut self) {
        unistd::close(self.fd).ok();
    }
}

#[cfg(test)]
mod tests {
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

    fn continue_subprocess(pid: Pid) {
        assert_eq!(
            waitpid(pid, Some(WaitPidFlag::WSTOPPED)).unwrap(),
            WaitStatus::Stopped(pid, SIGSTOP)
        );

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

    #[test]
    fn test_open_close_fpt() {
        let pid = subprocess(|| {});
        let fd = FptFd::new(pid, 1024, FptFlags::empty(), None).unwrap();
        continue_subprocess(pid);
        wait_for_finish(pid);

        drop(fd);
    }

    #[test]
    fn test_full() {
        let page_size = sysconf(SysconfVar::PAGE_SIZE).unwrap().unwrap() as usize;
        let cnt = 1024;

        let pid = subprocess(|| {
            let mut v = vec![0u8; page_size * cnt];

            v.fill(42);
        });

        let mut fd = FptFd::new(pid, 1024, FptFlags::empty(), None).unwrap();

        fd.enable().unwrap();
        continue_subprocess(pid);
        wait_for_finish(pid);
        fd.disable().unwrap();

        let mut buf = vec![0 as *const u8; 4096];
        let s = fd.read_fault(&mut buf, 0).unwrap();

        assert!(s >= cnt)
    }

    // TODO: test SIGTRAP
}
