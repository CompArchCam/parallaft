use std::ops::Range;

use nix::{sys::signal::Signal, unistd::Pid};
use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    check_coord::{CheckCoordinator, ProcessRole},
    dirty_page_trackers::{
        DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressTrackerContext,
        ExtraWritableRangesProvider,
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
    ($handlers_list:ident, fn $name:ident $( < $( $gen:tt ),+ > )? (& $($self_lifetime:lifetime)? self, $( $arg_name:ident : $arg_ty:ty ),* $(,)? ) ) => {
        fn $name(& $($self_lifetime)? self, $( $arg_name : $arg_ty ),*) -> Result<()> {
            for handler in &self.$handlers_list {
                handler.$name($( $arg_name ),*)?;
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

// fn handle_event<T>(list: &Vec<T>, )

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
    extra_writable_ranges_providers: Vec<&'a (dyn ExtraWritableRangesProvider + Sync)>,
    halt_hooks: Vec<&'a (dyn Halt + Sync)>,
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
            extra_writable_ranges_providers: Vec::new(),
            halt_hooks: Vec::new(),
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

    pub fn install_extra_writable_ranges_provider(
        &mut self,
        provider: &'a (dyn ExtraWritableRangesProvider + Sync),
    ) {
        self.extra_writable_ranges_providers.push(provider)
    }

    pub fn install_halt_hook(&mut self, hook: &'a (dyn Halt + Sync)) {
        self.halt_hooks.push(hook)
    }
}

impl<'a> ProcessLifetimeHook for Dispatcher<'a> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_main_init(context))
    }

    fn handle_checker_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_checker_init(context))
    }

    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        nr_dirty_pages: Option<usize>,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_checker_fini(nr_dirty_pages, context))
    }

    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_all_fini(context))
    }

    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        ret_val: i32,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        self.process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_main_fini(ret_val, context))
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
    generate_event_handler!(segment_event_handlers, fn handle_segment_created(&self, segment: &Segment));
    generate_event_handler!(segment_event_handlers, fn handle_segment_chain_closed(&self, segment: &Segment));
    generate_event_handler!(segment_event_handlers, fn handle_segment_ready(&self, segment: &mut Segment, checkpoint_end_caller: CheckpointCaller));
    generate_event_handler!(segment_event_handlers, fn handle_segment_checked(&self, segment: &Segment));
    generate_event_handler!(segment_event_handlers, fn handle_segment_removed(&self, segment: &Segment));
    generate_event_handler!(segment_event_handlers, fn handle_checkpoint_created_pre(&self, main_pid: Pid, last_segment_id: Option<SegmentId>));
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
    generate_event_handler!(schedule_checkpoint, fn schedule_checkpoint(&self, check_coord: &CheckCoordinator));
}

impl<'a> ScheduleCheckpointReady for Dispatcher<'a> {
    generate_event_handler!(schedule_checkpoint_ready_handlers, fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator));
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

impl<'a> ExtraWritableRangesProvider for Dispatcher<'a> {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]> {
        let mut ranges = Vec::new();

        for provider in &self.extra_writable_ranges_providers {
            ranges.append(&mut provider.get_extra_writable_ranges().into_vec());
        }

        ranges.into_boxed_slice()
    }
}

impl<'a> Halt for Dispatcher<'a> {
    fn halt(&self) {
        self.halt_hooks.iter().for_each(|h| h.halt())
    }
}

pub trait Installable<'a>
where
    Self: Sized,
{
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>);
}

pub trait Halt {
    fn halt(&self);
}
