use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    process::Process,
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, MainInitHandler, StandardSyscallHandler,
        SyscallHandlerExitAction,
    },
};

pub struct Dispatcher<'a> {
    main_init_handlers: Vec<&'a dyn MainInitHandler>,
    standard_syscall_handlers: Vec<&'a dyn StandardSyscallHandler>,
    custom_syscall_handlers: Vec<&'a dyn CustomSyscallHandler>,
}

impl<'a> Dispatcher<'a> {
    pub fn new() -> Self {
        Self {
            main_init_handlers: Vec::new(),
            standard_syscall_handlers: Vec::new(),
            custom_syscall_handlers: Vec::new(),
        }
    }

    pub fn install_main_init_handler(&mut self, handler: &'a dyn MainInitHandler) {
        self.main_init_handlers.push(handler)
    }

    pub fn handle_main_init(&self, process: &Process) {
        for handler in &self.main_init_handlers {
            handler.handle_main_init(process)
        }
    }

    pub fn install_standard_syscall_handler(&mut self, handler: &'a dyn StandardSyscallHandler) {
        self.standard_syscall_handlers.push(handler)
    }

    pub fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_entry(syscall, context);

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SyscallHandlerExitAction::NextHandler
    }

    pub fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit(ret_val, syscall, context);

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SyscallHandlerExitAction::NextHandler
    }

    pub fn install_custom_syscall_handler(&mut self, handler: &'a dyn CustomSyscallHandler) {
        self.custom_syscall_handlers.push(handler)
    }

    pub fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        for handler in &self.custom_syscall_handlers {
            let ret = handler.handle_custom_syscall_entry(sysno, args, context);

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SyscallHandlerExitAction::NextHandler
    }

    pub fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        for handler in &self.custom_syscall_handlers {
            let ret = handler.handle_custom_syscall_exit(ret_val, context);

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SyscallHandlerExitAction::NextHandler
    }
}

pub trait Installable<'a>
where
    Self: Sized,
{
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>);
}
