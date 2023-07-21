use nix::sys::signal::Signal;
use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    check_coord::CheckCoordinator,
    error::{Error, Result},
    inferior_rtlib::{ScheduleCheckpoint, ScheduleCheckpointReady},
    process::{dirty_pages::IgnoredPagesProvider, Process},
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    segments::{CheckpointCaller, Segment, SegmentEventHandler},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, ProcessLifetimeHook,
        StandardSyscallEntryCheckerHandlerExitAction, StandardSyscallEntryMainHandlerExitAction,
        StandardSyscallHandler, SyscallHandlerExitAction,
    },
    throttler::Throttler,
};

fn run_handler<T: ?Sized, R>(f: impl Fn(&T) -> Result<R>, handlers: &[&T]) -> Result<R> {
    let mut ret: Result<R> = Err(Error::NotSupported);
    for &handler in handlers {
        ret = f(handler);
        if let Err(Error::NotSupported) = ret {
            continue;
        }
    }
    ret
}

pub struct Dispatcher<'a> {
    process_lifetime_hooks: Vec<&'a (dyn ProcessLifetimeHook + Sync)>,
    standard_syscall_handlers: Vec<&'a (dyn StandardSyscallHandler + Sync)>,
    custom_syscall_handlers: Vec<&'a (dyn CustomSyscallHandler + Sync)>,
    signal_handlers: Vec<&'a (dyn SignalHandler + Sync)>,
    segment_event_handlers: Vec<&'a (dyn SegmentEventHandler + Sync)>,
    ignored_pages_providers: Vec<&'a (dyn IgnoredPagesProvider + Sync)>,
    throttlers: Vec<&'a (dyn Throttler + Sync)>,
    schedule_checkpoint: Vec<&'a (dyn ScheduleCheckpoint + Sync)>,
    schedule_checkpoint_ready_handlers: Vec<&'a (dyn ScheduleCheckpointReady + Sync)>,
}

impl<'a> Dispatcher<'a> {
    pub fn new() -> Self {
        Self {
            process_lifetime_hooks: Vec::new(),
            standard_syscall_handlers: Vec::new(),
            custom_syscall_handlers: Vec::new(),
            signal_handlers: Vec::new(),
            segment_event_handlers: Vec::new(),
            ignored_pages_providers: Vec::new(),
            throttlers: Vec::new(),
            schedule_checkpoint: Vec::new(),
            schedule_checkpoint_ready_handlers: Vec::new(),
        }
    }

    pub fn install_process_lifetime_hook(&mut self, handler: &'a (dyn ProcessLifetimeHook + Sync)) {
        self.process_lifetime_hooks.push(handler)
    }

    pub fn install_standard_syscall_handler(
        &mut self,
        handler: &'a (dyn StandardSyscallHandler + Sync),
    ) {
        self.standard_syscall_handlers.push(handler)
    }

    pub fn install_custom_syscall_handler(
        &mut self,
        handler: &'a (dyn CustomSyscallHandler + Sync),
    ) {
        self.custom_syscall_handlers.push(handler)
    }

    pub fn install_signal_handler(&mut self, handler: &'a (dyn SignalHandler + Sync)) {
        self.signal_handlers.push(handler)
    }

    pub fn install_segment_event_handler(&mut self, handler: &'a (dyn SegmentEventHandler + Sync)) {
        self.segment_event_handlers.push(handler)
    }

    pub fn install_throttler(&mut self, throttler: &'a (dyn Throttler + Sync)) {
        self.throttlers.push(throttler)
    }

    pub fn install_ignored_pages_provider(
        &mut self,
        provider: &'a (dyn IgnoredPagesProvider + Sync),
    ) {
        self.ignored_pages_providers.push(provider)
    }

    pub fn install_schedule_checkpoint(&mut self, scheduler: &'a (dyn ScheduleCheckpoint + Sync)) {
        self.schedule_checkpoint.push(scheduler)
    }

    pub fn install_schedule_checkpoint_ready_handler(
        &mut self,
        handler: &'a (dyn ScheduleCheckpointReady + Sync),
    ) {
        self.schedule_checkpoint_ready_handlers.push(handler)
    }

    pub fn dispatch_throttle(
        &self,
        nr_dirty_pages: usize,
        check_coord: &CheckCoordinator,
    ) -> Option<&'a (dyn Throttler + Sync)> {
        for &handler in &self.throttlers {
            if handler.should_throttle(nr_dirty_pages, check_coord) {
                return Some(handler);
            }
        }

        None
    }
}

impl<'a> ProcessLifetimeHook for Dispatcher<'a> {
    fn handle_main_init(&self, process: &Process) -> Result<()> {
        for handler in &self.process_lifetime_hooks {
            handler.handle_main_init(process)?;
        }

        Ok(())
    }

    fn handle_checker_init(&self, process: &Process) -> Result<()> {
        for handler in &self.process_lifetime_hooks {
            handler.handle_checker_init(process)?;
        }

        Ok(())
    }

    fn handle_checker_fini(&self, process: &Process, nr_dirty_pages: Option<usize>) -> Result<()> {
        for handler in &self.process_lifetime_hooks {
            handler.handle_checker_fini(process, nr_dirty_pages)?;
        }

        Ok(())
    }

    fn handle_all_fini(&self) -> Result<()> {
        for handler in &self.process_lifetime_hooks {
            handler.handle_all_fini()?;
        }

        Ok(())
    }

    fn handle_main_fini(&self, ret_val: i32) -> Result<()> {
        for handler in &self.process_lifetime_hooks {
            handler.handle_main_fini(ret_val)?;
        }

        Ok(())
    }
}

impl<'a> StandardSyscallHandler for Dispatcher<'a> {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_entry(syscall, context)?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit(ret_val, syscall, context)?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        for handler in &self.standard_syscall_handlers {
            let ret =
                handler.handle_standard_syscall_entry_main(syscall, active_segment, context)?;

            if !matches!(ret, StandardSyscallEntryMainHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit_main(
                ret_val,
                saved_incomplete_syscall,
                active_segment,
                context,
            )?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        for handler in &self.standard_syscall_handlers {
            let ret =
                handler.handle_standard_syscall_entry_checker(syscall, active_segment, context)?;

            if !matches!(
                ret,
                StandardSyscallEntryCheckerHandlerExitAction::NextHandler
            ) {
                return Ok(ret);
            }
        }

        Ok(StandardSyscallEntryCheckerHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit_checker(
        &self,
        ret_val: isize,
        saved_syscall: &SavedSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit_checker(
                ret_val,
                saved_syscall,
                active_segment,
                context,
            )?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> CustomSyscallHandler for Dispatcher<'a> {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.custom_syscall_handlers {
            let ret = handler.handle_custom_syscall_entry(sysno, args, context)?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.custom_syscall_handlers {
            let ret = handler.handle_custom_syscall_exit(ret_val, context)?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a> SignalHandler for Dispatcher<'a> {
    fn handle_signal(
        &self,
        signal: Signal,
        context: &HandlerContext,
    ) -> Result<SignalHandlerExitAction> {
        for handler in &self.signal_handlers {
            let ret = handler.handle_signal(signal, context)?;

            if !matches!(ret, SignalHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl<'a> SegmentEventHandler for Dispatcher<'a> {
    fn handle_segment_ready(
        &self,
        segment: &mut Segment,
        checkpoint_end_caller: CheckpointCaller,
    ) -> Result<()> {
        for handler in &self.segment_event_handlers {
            handler.handle_segment_ready(segment, checkpoint_end_caller)?;
        }

        Ok(())
    }
}

impl<'a> IgnoredPagesProvider for Dispatcher<'a> {
    fn get_ignored_pages(&self) -> Box<[usize]> {
        let mut pages = Vec::new();

        for provider in &self.ignored_pages_providers {
            pages.append(&mut provider.get_ignored_pages().into_vec());
        }

        pages.into_boxed_slice()
    }
}

impl<'a> ScheduleCheckpoint for Dispatcher<'a> {
    fn schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()> {
        run_handler(
            |s| s.schedule_checkpoint(check_coord),
            &self.schedule_checkpoint,
        )
    }
}

impl<'a> ScheduleCheckpointReady for Dispatcher<'a> {
    fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()> {
        for &handler in &self.schedule_checkpoint_ready_handlers {
            handler.handle_ready_to_schedule_checkpoint(check_coord)?;
        }

        Ok(())
    }
}

pub trait Installable<'a>
where
    Self: Sized,
{
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>);
}
