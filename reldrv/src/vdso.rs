use log::info;
use reverie_syscalls::{Addr, MemoryAccess, Syscall};

use crate::{
    dispatcher::{Dispatcher, Installable},
    process::Process,
    syscall_handlers::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction},
};

pub struct VdsoRemover;

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
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        if ret_val == 0 {
            match syscall {
                Syscall::Execve(_) | Syscall::Execveat(_) => {
                    let process = context.process;
                    let sp = process.read_registers().rsp;
                    let mut addr = Addr::<u64>::from_raw(sp as _).unwrap();

                    let mut zero_count: i32 = 2;
                    while zero_count > 0 {
                        let t = process.read_value(addr).unwrap();
                        if t == 0 {
                            zero_count -= 1;
                        }
                        addr = unsafe { addr.add(1) };
                    }

                    loop {
                        let v = process.read_value(addr).unwrap();

                        if v == nix::libc::AT_NULL {
                            break;
                        }

                        if v == nix::libc::AT_SYSINFO_EHDR {
                            Process::new(process.pid) // TODO
                            .write_value(unsafe { addr.into_mut() }, &nix::libc::AT_IGNORE)
                            .unwrap();

                            info!(
                                "vDSO removed at offset {:p}",
                                (addr.as_raw() - sp as usize) as *const u8
                            );

                            break;
                        }

                        addr = unsafe { addr.add(2) };
                    }
                }
                _ => (),
            }
        }
        SyscallHandlerExitAction::NextHandler
    }
}

impl<'a> Installable<'a> for VdsoRemover {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
    }
}
