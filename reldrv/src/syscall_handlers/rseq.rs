use log::info;
use nix::sys::ptrace;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    process::{ProcessLifetimeHook, ProcessLifetimeHookContext},
};

use super::{HandlerContext, StandardSyscallHandler, SyscallHandlerExitAction};

pub struct RseqHandler {}

impl RseqHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for RseqHandler {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        let process = context.process();

        Ok(match syscall {
            Syscall::Rseq(_) => {
                process.modify_registers_with(|regs| regs.with_syscall_skipped())?;
                SyscallHandlerExitAction::ContinueInferior
            }
            _ => SyscallHandlerExitAction::NextHandler,
        })
    }

    fn handle_standard_syscall_exit(
        &self,
        _ret_val: isize,
        syscall: &Syscall,
        _context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(match syscall {
            Syscall::Rseq(_) => SyscallHandlerExitAction::ContinueInferior,
            _ => SyscallHandlerExitAction::NextHandler,
        })
    }
}

impl ProcessLifetimeHook for RseqHandler {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        let rseq_config = ptrace::get_rseq_configuration(context.process.pid).unwrap();

        if rseq_config.rseq_abi_pointer != 0 {
            let ret = context.process.syscall_direct(
                syscalls::Sysno::rseq,
                syscalls::syscall_args!(
                    rseq_config.rseq_abi_pointer as _,
                    rseq_config.rseq_abi_size as _,
                    1,
                    rseq_config.signature as _
                ),
                true,
                false,
                true,
            )?;
            assert_eq!(ret, 0);
            info!("Rseq unregistered");
        }

        Ok(())
    }
}

impl Module for RseqHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_standard_syscall_handler(self);
    }
}
