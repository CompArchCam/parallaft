use super::{state::ProcessState, Process};
use crate::error::Result;

#[allow(non_camel_case_types)]
#[repr(C)]
#[derive(Debug, Clone, Copy)]
struct siginfo_t_inner {
    si_signo: nix::libc::c_int,
    si_errno: nix::libc::c_int,
    si_code: nix::libc::c_int,
    si_pid: nix::libc::c_int,
    si_uid: nix::libc::c_int,
    si_ptr: *mut nix::libc::c_void,
}

#[repr(C)]
union siginfo_t {
    si: siginfo_t_inner,
    si_pad: [nix::libc::c_int; 128 / core::mem::size_of::<nix::libc::c_int>()],
}

impl<S: ProcessState> Process<S> {
    pub fn sigqueue(&self, value: usize) -> Result<()> {
        unsafe {
            nix::libc::syscall(
                nix::libc::SYS_rt_sigqueueinfo,
                self.pid.as_raw(),
                nix::libc::SIGUSR1,
                &siginfo_t {
                    si: siginfo_t_inner {
                        si_signo: nix::libc::SIGUSR1,
                        si_errno: 0,
                        si_code: -1, /* SI_QUEUE */
                        si_pid: 0,
                        si_uid: 0,
                        si_ptr: value as *mut nix::libc::c_void,
                    },
                },
            )
        };
        Ok(())
    }
}
