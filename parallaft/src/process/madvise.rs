use std::os::fd::AsRawFd;

use nix::{errno::Errno, libc};

use super::{state::ProcessState, Process};
use crate::error::Result;

impl<S: ProcessState> Process<S> {
    pub fn madvise(&self, iovec: &[std::io::IoSlice], advice: libc::c_int) -> Result<usize> {
        let pidfd_fd = self.pidfd()?;

        let res = unsafe {
            libc::syscall(
                libc::SYS_process_madvise,
                pidfd_fd.as_raw_fd(),
                iovec.as_ptr(),
                iovec.len(),
                advice,
                0,
            )
        };

        Errno::result(res).map_err(|e| e.into()).map(|r| r as usize)
    }
}
