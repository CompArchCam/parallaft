use nix::{
    errno::Errno,
    sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec},
    unistd::Pid,
};
use reverie_syscalls::MemoryAccess;

pub struct RemoteMemory {
    pid: Pid,
}

impl RemoteMemory {
    pub fn new(pid: Pid) -> Self {
        Self { pid }
    }
}

impl MemoryAccess for RemoteMemory {
    fn read_vectored(
        &self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> Result<usize, reverie_syscalls::Errno> {
        let remote_iov: Vec<RemoteIoVec> = read_from
            .iter()
            .map(|io_slice| RemoteIoVec {
                base: io_slice.as_ptr() as _,
                len: io_slice.len(),
            })
            .collect();

        process_vm_readv(self.pid, write_to, &remote_iov).map_err(|e| match e {
            Errno::EFAULT => reverie_syscalls::Errno::EFAULT,
            Errno::EINVAL => reverie_syscalls::Errno::EINVAL,
            Errno::ENOMEM => reverie_syscalls::Errno::ENOMEM,
            Errno::EPERM => reverie_syscalls::Errno::EPERM,
            Errno::ESRCH => reverie_syscalls::Errno::ESRCH,
            _ => reverie_syscalls::Errno::ENODATA,
        })
    }

    fn write_vectored(
        &mut self,
        read_from: &[std::io::IoSlice],
        write_to: &mut [std::io::IoSliceMut],
    ) -> Result<usize, reverie_syscalls::Errno> {
        let remote_iov: Vec<RemoteIoVec> = write_to
            .iter()
            .map(|io_slice| RemoteIoVec {
                base: io_slice.as_ptr() as _,
                len: io_slice.len(),
            })
            .collect();

        process_vm_writev(self.pid, read_from, &remote_iov).map_err(|e| match e {
            Errno::EFAULT => reverie_syscalls::Errno::EFAULT,
            Errno::EINVAL => reverie_syscalls::Errno::EINVAL,
            Errno::ENOMEM => reverie_syscalls::Errno::ENOMEM,
            Errno::EPERM => reverie_syscalls::Errno::EPERM,
            Errno::ESRCH => reverie_syscalls::Errno::ESRCH,
            _ => reverie_syscalls::Errno::ENODATA,
        })
    }
}
