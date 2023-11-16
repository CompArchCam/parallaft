use std::sync::atomic::{AtomicBool, Ordering};

use log::info;
use nix::{libc::ptrace_rseq_configuration, sys::ptrace};
use parking_lot::Mutex;
use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::Result,
    process::Process,
};

use super::{
    CustomSyscallHandler, HandlerContext, ProcessLifetimeHook, StandardSyscallHandler,
    SyscallHandlerExitAction,
};

pub struct RseqHandler {
    rseq_config: Mutex<Option<ptrace_rseq_configuration>>,
    execve_done: AtomicBool,
}

impl RseqHandler {
    pub fn new() -> Self {
        Self {
            rseq_config: Mutex::new(None),
            execve_done: AtomicBool::new(false),
        }
    }

    pub fn unregister_rseq(&self, process: &Process) -> Result<()> {
        if let Some(rseq_config) = self.rseq_config.lock().take() {
            let ret = process.syscall_direct(
                syscalls::Sysno::rseq,
                syscalls::syscall_args!(
                    rseq_config.rseq_abi_pointer as _,
                    rseq_config.rseq_abi_size as _,
                    1,
                    rseq_config.signature as _
                ),
                true,
                false,
                false,
            )?;
            assert_eq!(ret, 0);
            info!("rseq unregistered");
        }

        Ok(())
    }
}

impl StandardSyscallHandler for RseqHandler {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        let process = context.process;

        Ok(match syscall {
            Syscall::Rseq(_) => {
                process.modify_registers_with(|regs| regs.with_syscall_skipped())?;

                SyscallHandlerExitAction::ContinueInferior
            }
            Syscall::Execve(_) | Syscall::Execveat(_) => {
                self.execve_done.store(true, Ordering::SeqCst);
                SyscallHandlerExitAction::NextHandler
            }
            _ => SyscallHandlerExitAction::NextHandler,
        })
    }

    fn handle_standard_syscall_exit(
        &self,
        _ret_val: isize,
        syscall: &Syscall,
        _context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(match syscall {
            Syscall::Rseq(_) => SyscallHandlerExitAction::ContinueInferior,
            _ => SyscallHandlerExitAction::NextHandler,
        })
    }
}

impl CustomSyscallHandler for RseqHandler {
    fn handle_custom_syscall_entry(
        &self,
        _sysno: usize,
        _args: SyscallArgs,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if !self.execve_done.load(Ordering::SeqCst) {
            self.unregister_rseq(context.process)?;
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for RseqHandler {
    fn handle_main_init(&self, process: &Process) -> Result<()> {
        let rseq_config = ptrace::get_rseq_configuration(process.pid)
            .ok()
            .and_then(|c| {
                if c.rseq_abi_pointer == 0 {
                    None
                } else {
                    Some(c)
                }
            });

        *self.rseq_config.lock() = rseq_config;

        Ok(())
    }
}

impl<'a> Installable<'a> for RseqHandler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
        dispatcher.install_standard_syscall_handler(self);
        dispatcher.install_custom_syscall_handler(self);
    }
}
