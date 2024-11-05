use log::info;
use nix::sys::ptrace;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{registers::RegisterAccess, state::Stopped},
    types::process_id::Main,
};

pub struct RseqHandler {}

impl Default for RseqHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl RseqHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for RseqHandler {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        mut context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        let process = context.process_mut();

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
        _context: HandlerContextWithInferior<Stopped>,
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
        main: &mut Main<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        let rseq_config = ptrace::get_rseq_configuration(main.process().pid).unwrap();

        if rseq_config.rseq_abi_pointer != 0 {
            let ret = main.try_map_process_inplace(|p| {
                p.syscall_direct(
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
                )
            })?;

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
