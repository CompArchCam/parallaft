use nix::sys::signal::Signal;
use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    process::Process,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    segments::Segment,
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, MainInitHandler,
        StandardSyscallEntryCheckerHandlerExitAction, StandardSyscallEntryMainHandlerExitAction,
        StandardSyscallHandler, SyscallHandlerExitAction,
    },
};

pub struct Dispatcher<'a> {
    main_init_handlers: Vec<&'a dyn MainInitHandler>,
    standard_syscall_handlers: Vec<&'a dyn StandardSyscallHandler>,
    custom_syscall_handlers: Vec<&'a dyn CustomSyscallHandler>,
    signal_handlers: Vec<&'a dyn SignalHandler>,
}

impl<'a> Dispatcher<'a> {
    pub fn new() -> Self {
        Self {
            main_init_handlers: Vec::new(),
            standard_syscall_handlers: Vec::new(),
            custom_syscall_handlers: Vec::new(),
            signal_handlers: Vec::new(),
        }
    }

    pub fn install_main_init_handler(&mut self, handler: &'a dyn MainInitHandler) {
        self.main_init_handlers.push(handler)
    }

    pub fn install_standard_syscall_handler(&mut self, handler: &'a dyn StandardSyscallHandler) {
        self.standard_syscall_handlers.push(handler)
    }

    pub fn install_custom_syscall_handler(&mut self, handler: &'a dyn CustomSyscallHandler) {
        self.custom_syscall_handlers.push(handler)
    }

    pub fn install_signal_handler(&mut self, handler: &'a dyn SignalHandler) {
        self.signal_handlers.push(handler)
    }
}

impl<'a> MainInitHandler for Dispatcher<'a> {
    fn handle_main_init(&self, process: &Process) {
        for handler in &self.main_init_handlers {
            handler.handle_main_init(process)
        }
    }
}

impl<'a> StandardSyscallHandler for Dispatcher<'a> {
    fn handle_standard_syscall_entry(
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

    fn handle_standard_syscall_exit(
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

    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> StandardSyscallEntryMainHandlerExitAction {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_entry_main(syscall, active_segment, context);

            if !matches!(ret, StandardSyscallEntryMainHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        StandardSyscallEntryMainHandlerExitAction::NextHandler
    }

    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit_main(
                ret_val,
                saved_incomplete_syscall,
                active_segment,
                context,
            );

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SyscallHandlerExitAction::NextHandler
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> StandardSyscallEntryCheckerHandlerExitAction {
        for handler in &self.standard_syscall_handlers {
            let ret =
                handler.handle_standard_syscall_entry_checker(syscall, active_segment, context);

            if !matches!(
                ret,
                StandardSyscallEntryCheckerHandlerExitAction::NextHandler
            ) {
                return ret;
            }
        }

        StandardSyscallEntryCheckerHandlerExitAction::NextHandler
    }

    fn handle_standard_syscall_exit_checker(
        &self,
        ret_val: isize,
        saved_syscall: &SavedSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit_checker(
                ret_val,
                saved_syscall,
                active_segment,
                context,
            );

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SyscallHandlerExitAction::NextHandler
    }
}

impl<'a> CustomSyscallHandler for Dispatcher<'a> {
    fn handle_custom_syscall_entry(
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

    fn handle_custom_syscall_exit(
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

impl<'a> SignalHandler for Dispatcher<'a> {
    fn handle_signal(&self, signal: Signal, context: &HandlerContext) -> SignalHandlerExitAction {
        for handler in &self.signal_handlers {
            let ret = handler.handle_signal(signal, context);

            if !matches!(ret, SignalHandlerExitAction::NextHandler) {
                return ret;
            }
        }

        SignalHandlerExitAction::NextHandler
    }
}

pub trait Installable<'a>
where
    Self: Sized,
{
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>);
}
