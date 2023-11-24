use nix::{sys::signal::Signal, unistd::Pid};
use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    check_coord::{CheckCoordinator, ProcessRole},
    dirty_page_trackers::{
        DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressTrackerContext,
    },
    error::Result,
    inferior_rtlib::{ScheduleCheckpoint, ScheduleCheckpointReady},
    process::{dirty_pages::IgnoredPagesProvider, ProcessLifetimeHook, ProcessLifetimeHookContext},
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    segments::{CheckpointCaller, Segment, SegmentChain, SegmentEventHandler, SegmentId},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, StandardSyscallEntryCheckerHandlerExitAction,
        StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
        SyscallHandlerExitAction,
    },
    throttlers::Throttler,
};

macro_rules! generate_event_handler {
    ($handlers_list:ident, $event_method:ident $(, $param:ident : $param_type:ty)*) => {
        fn $event_method(&self $(, $param : $param_type)*) -> Result<()> {
            for handler in &self.$handlers_list {
                handler.$event_method($( $param ),*)?;
            }

            Ok(())
        }
    };
}

macro_rules! generate_event_handler_option {
    ($handler_option:ident, fn $name:ident $( < $( $gen:tt ),+ > )? (&self, $( $arg_name:ident : $arg_ty:ty ),* $(,)? ) $( -> $ret_ty:ty )? ) => {
        fn $name $( < $( $gen ),+ > )? ( &self, $( $arg_name : $arg_ty ),* ) $( -> $ret_ty )? {
            self.$handler_option.ok_or($crate::error::Error::NotHandled)?.$name($( $arg_name ),*)
        }
    };
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
    dirty_page_tracker: Option<&'a (dyn DirtyPageAddressTracker + Sync)>,
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
            dirty_page_tracker: None,
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
        segments: &SegmentChain,
        check_coord: &CheckCoordinator,
    ) -> Option<&'a (dyn Throttler + Sync)> {
        for &handler in &self.throttlers {
            if handler.should_throttle(nr_dirty_pages, segments, check_coord) {
                return Some(handler);
            }
        }

        None
    }

    pub fn install_dirty_page_tracker(
        &mut self,
        tracker: &'a (dyn DirtyPageAddressTracker + Sync),
    ) {
        self.dirty_page_tracker = Some(tracker);
    }
}

impl<'a> ProcessLifetimeHook for Dispatcher<'a> {
    generate_event_handler!(process_lifetime_hooks, handle_main_init, context: &ProcessLifetimeHookContext);
    generate_event_handler!(process_lifetime_hooks, handle_checker_init, context: &ProcessLifetimeHookContext);
    generate_event_handler!(process_lifetime_hooks, handle_checker_fini, nr_dirty_pages: Option<usize>, context: &ProcessLifetimeHookContext);
    generate_event_handler!(process_lifetime_hooks, handle_all_fini, context: &ProcessLifetimeHookContext);
    generate_event_handler!(process_lifetime_hooks, handle_main_fini, ret_val: i32, context: &ProcessLifetimeHookContext);
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
    fn handle_signal<'s, 'p, 'segs, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: &HandlerContext<'p, 'segs, 'disp, 'scope, 'env>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
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
    generate_event_handler!(segment_event_handlers, handle_segment_created, segment: &Segment);
    generate_event_handler!(segment_event_handlers, handle_segment_chain_closed, segment: &Segment);
    generate_event_handler!(segment_event_handlers, handle_segment_ready, segment: &mut Segment, checkpoint_end_caller: CheckpointCaller);
    generate_event_handler!(segment_event_handlers, handle_segment_checked, segment: &Segment);
    generate_event_handler!(segment_event_handlers, handle_segment_removed, segment: &Segment);
    generate_event_handler!(segment_event_handlers, handle_checkpoint_created_pre, main_pid: Pid, last_segment_id: Option<SegmentId>);
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
    generate_event_handler!(schedule_checkpoint, schedule_checkpoint, check_coord: &CheckCoordinator);
}

impl<'a> ScheduleCheckpointReady for Dispatcher<'a> {
    generate_event_handler!(schedule_checkpoint_ready_handlers, handle_ready_to_schedule_checkpoint, check_coord: &CheckCoordinator);
}

impl<'a> DirtyPageAddressTracker for Dispatcher<'a> {
    generate_event_handler_option!(dirty_page_tracker,
        fn take_dirty_pages_addresses<'b>(
            &self,
            segment_id: SegmentId,
            role: ProcessRole,
            ctx: &DirtyPageAddressTrackerContext<'b>,
        ) -> Result<(Box<dyn AsRef<[usize]>>, DirtyPageAddressFlags)>
    );
}

pub trait Installable<'a>
where
    Self: Sized,
{
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>);
}
