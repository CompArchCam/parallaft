use super::Process;

use compel::ParasiteCtl;
use log::debug;
use parasite::commands::{Request, Response};
use syscalls::{SyscallArgs, Sysno};

impl Process {
    pub fn compel_prepare<T: Send + Copy, R: Send + Copy>(&self) -> ParasiteCtl<T, R> {
        compel::ParasiteCtl::<T, R>::prepare(self.pid.as_raw())
            .expect("failed to prepare parasite ctl")
    }

    pub fn syscall(&self, nr: Sysno, args: SyscallArgs) -> i64 {
        self.compel_prepare::<Request, Response>()
            .syscall(nr, args)
            .expect("failed to make remote syscall")
    }
}
