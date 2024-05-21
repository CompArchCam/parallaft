use super::Process;
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

impl Process {
    pub fn sigqueue(&self, value: usize) -> Result<()> {
        unsafe {
            nix::libc::syscall(
                nix::libc::SYS_rt_sigqueueinfo,
                self.pid.as_raw(),
                nix::libc::SIGTRAP,
                &siginfo_t {
                    si: siginfo_t_inner {
                        si_signo: nix::libc::SIGTRAP,
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

    pub fn get_sigval(&self) -> Result<Option<usize>> {
        let siginfo = self.get_siginfo()?;

        if siginfo.si_signo == nix::libc::SIGTRAP && siginfo.si_code == -1
        /* SI_QUEUE */
        {
            return Ok(Some(unsafe { siginfo.si_value().sival_ptr } as usize));
        } else {
            return Ok(None);
        }
    }
}
