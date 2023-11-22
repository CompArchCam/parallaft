use nix::ioctl_none;

use nix::ioctl_read;
use nix::ioctl_write_ptr;
use nix::libc;

#[repr(C)]
pub struct FptReadFaultRequest {
    pub buffer: *mut libc::size_t,
    pub size: libc::size_t,
    pub offset: libc::size_t,
}

#[repr(C)]
pub struct FptAttachRequest {
    pub pid: libc::pid_t,
    pub buffer_size: libc::size_t,
    pub flags: libc::c_int,
    pub watermark: libc::size_t,
}

ioctl_write_ptr!(fptioc_attach_process, b'k', 0, FptAttachRequest);
ioctl_none!(fptioc_clear_fault, b'k', 1);
ioctl_write_ptr!(fptioc_read_fault, b'k', 2, FptReadFaultRequest);
ioctl_none!(fptioc_enable, b'k', 3);
ioctl_none!(fptioc_disable, b'k', 4);
ioctl_read!(fptioc_get_lost_count, b'k', 5, libc::size_t);
ioctl_read!(fptioc_get_count, b'k', 6, libc::size_t);
ioctl_none!(fptioc_new_buffer, b'k', 7);
ioctl_read!(fptioc_get_buffer_size, b'k', 8, libc::size_t);
