use log::info;
use reverie_syscalls::{MemoryAccess, Syscall};

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::Process,
};

pub struct VdsoRemover;

impl Default for VdsoRemover {
    fn default() -> Self {
        Self::new()
    }
}

impl VdsoRemover {
    pub fn new() -> Self {
        info!("vDSO remover initialized");
        Self {}
    }
}

impl StandardSyscallHandler for VdsoRemover {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if ret_val == 0 {
            match syscall {
                Syscall::Execve(_) | Syscall::Execveat(_) => {
                    let process = context.process();
                    let sp = process.read_registers()?.sp() as usize;
                    let mut addr = sp;

                    let mut zero_count: i32 = 2;
                    while zero_count > 0 {
                        let t = process.read_value::<_, u64>(addr)?;
                        if t == 0 {
                            zero_count -= 1;
                        }
                        addr += 8;
                    }

                    loop {
                        let v = process.read_value::<_, u64>(addr)?;

                        if v == nix::libc::AT_NULL {
                            break;
                        }

                        if v == nix::libc::AT_SYSINFO_EHDR {
                            Process::new(process.pid) // TODO
                            .write_value(sp, &nix::libc::AT_IGNORE)?;

                            info!("vDSO removed at offset {:p}", (addr - sp) as *const u8);

                            break;
                        }

                        addr += 16;
                    }
                }
                _ => (),
            }
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for VdsoRemover {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
