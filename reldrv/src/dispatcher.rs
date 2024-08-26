use std::{ops::Range, sync::Arc, thread::Scope};

use nix::sys::signal::Signal;
use parking_lot::RwLock;
use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;
use typed_arena::Arena;

use crate::{
    check_coord::CheckCoordinator,
    dirty_page_trackers::{
        DirtyPageAddressTracker, DirtyPageAddressesWithFlags, ExtraWritableRangesProvider,
    },
    error::Result,
    events::{
        comparator::{
            MemoryComparator, MemoryComparsionResult, RegisterComparator, RegisterComparsionResult,
        },
        hctx,
        insn_patching::InstructionPatchingEventHandler,
        memory::MemoryEventHandler,
        migration::MigrationHandler,
        module_lifetime::ModuleLifetimeHook,
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{
            CustomSyscallHandler, StandardSyscallEntryCheckerHandlerExitAction,
            StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
            SyscallHandlerExitAction,
        },
        HandlerContext,
    },
    exec_point_providers::ExecutionPointProvider,
    helpers::insn_patcher::Patch,
    inferior_rtlib::{ScheduleCheckpoint, ScheduleCheckpointReady},
    process::{
        dirty_pages::IgnoredPagesProvider,
        registers::Registers,
        state::{Running, Stopped},
        Process,
    },
    statistics::{StatisticValue, StatisticsProvider},
    throttlers::Throttler,
    types::{
        chains::SegmentChains,
        checker::CheckFailReason,
        execution_point::ExecutionPoint,
        exit_reason::ExitReason,
        memory_map::MemoryMap,
        process_id::{Checker, InferiorId, InferiorRefMut, Main},
        segment::Segment,
        segment_record::saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    },
};

macro_rules! generate_event_handler {
    ($handlers_list:ident, fn $name:ident $( < $( $gen:tt ),+ > )? (& $($self_lifetime:lifetime)? self, $( $arg_name:ident : $arg_ty:ty ),* $(,)? ) ) => {
        fn $name(& $($self_lifetime)? self, $( $arg_name : $arg_ty ),*) -> Result<()> {
            for handler in &self.subscribers.read().$handlers_list {
                handler.$name($( $arg_name ),*)?;
            }

            Ok(())
        }
    };
}

macro_rules! generate_event_handler_option {
    ($handler_option:ident, fn $name:ident $( < $( $gen:tt ),+ > )? (&self, $( $arg_name:ident : $arg_ty:ty ),* $(,)? ) $( -> $ret_ty:ty )? ) => {
        fn $name $( < $( $gen ),+ > )? ( &self, $( $arg_name : $arg_ty ),* ) $( -> $ret_ty )? {
            self.subscribers.read().$handler_option.ok_or($crate::error::Error::NotHandled)?.$name($( $arg_name ),*)
        }
    };
}

pub struct Subscribers<'a> {
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
    stats_providers: Vec<&'a (dyn StatisticsProvider + Sync)>,
    register_comparators: Vec<&'a (dyn RegisterComparator + Sync)>,
    memory_comparators: Vec<&'a dyn MemoryComparator>,
    module_lifetime_hooks: Vec<&'a dyn ModuleLifetimeHook>,
    exec_point_provider: Option<&'a dyn ExecutionPointProvider>,
    memory_event_handlers: Vec<&'a dyn MemoryEventHandler>,
    instruction_patching_events_handlers: Vec<&'a dyn InstructionPatchingEventHandler>,
    migration_handlers: Vec<&'a dyn MigrationHandler>,
}

impl<'a> Default for Subscribers<'a> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a> Subscribers<'a> {
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
            stats_providers: Vec::new(),
            register_comparators: Vec::new(),
            memory_comparators: Vec::new(),
            module_lifetime_hooks: Vec::new(),
            exec_point_provider: None,
            memory_event_handlers: Vec::new(),
            instruction_patching_events_handlers: Vec::new(),
            migration_handlers: Vec::new(),
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

    pub fn set_dirty_page_tracker(&mut self, tracker: &'a (dyn DirtyPageAddressTracker + Sync)) {
        self.dirty_page_tracker = Some(tracker);
    }

    pub fn install_extra_writable_ranges_provider(
        &mut self,
        provider: &'a (dyn ExtraWritableRangesProvider + Sync),
    ) {
        self.extra_writable_ranges_providers.push(provider)
    }

    pub fn install_stats_providers(&mut self, provider: &'a (dyn StatisticsProvider + Sync)) {
        self.stats_providers.push(provider)
    }

    pub fn install_register_comparator(&mut self, comparator: &'a (dyn RegisterComparator + Sync)) {
        self.register_comparators.push(comparator)
    }

    pub fn install_memory_comparator(&mut self, comparator: &'a dyn MemoryComparator) {
        self.memory_comparators.push(comparator)
    }

    pub fn install_module_lifetime_hook(&mut self, hook: &'a dyn ModuleLifetimeHook) {
        self.module_lifetime_hooks.push(hook)
    }

    pub fn set_execution_point_provider(&mut self, provider: &'a dyn ExecutionPointProvider) {
        self.exec_point_provider = Some(provider);
    }

    pub fn install_memory_event_handler(&mut self, handler: &'a dyn MemoryEventHandler) {
        self.memory_event_handlers.push(handler)
    }

    pub fn install_instruction_patching_events_handler(
        &mut self,
        handler: &'a dyn InstructionPatchingEventHandler,
    ) {
        self.instruction_patching_events_handlers.push(handler)
    }

    pub fn install_migration_handler(&mut self, handler: &'a dyn MigrationHandler) {
        self.migration_handlers.push(handler)
    }
}

pub struct Dispatcher<'a, 'm> {
    modules: Arena<Box<dyn Module + 'm>>,
    subscribers: RwLock<Subscribers<'a>>,
}

impl<'a, 'm> Default for Dispatcher<'a, 'm> {
    fn default() -> Self {
        Self::new()
    }
}

impl<'a, 'm> Dispatcher<'a, 'm> {
    pub fn new() -> Self {
        Self {
            modules: Arena::new(),
            subscribers: RwLock::new(Subscribers::new()),
        }
    }

    pub fn dispatch_throttle(
        &self,
        main: &mut Main<Stopped>,
        segments: &SegmentChains,
        check_coord: &CheckCoordinator,
    ) -> Option<&'a (dyn Throttler + Sync)> {
        self.subscribers
            .read()
            .throttlers
            .iter()
            .find(|&&handler| handler.should_throttle(main, segments, check_coord))
            .copied()
    }

    pub fn register_module<'s, T>(&'s self, module: T) -> &T
    where
        T: Module + 'm,
        's: 'a,
    {
        let m = self.modules.alloc(Box::new(module));
        let mut subscribers = self.subscribers.write();

        m.subscribe_all(&mut subscribers);

        unsafe { &*(m.as_ref() as *const _ as *const T) }
    }

    pub fn register_module_boxed<'s>(&'s self, module: Box<dyn Module>)
    where
        's: 'a,
    {
        let mut subscribers = self.subscribers.write();
        let m = self.modules.alloc(module);

        m.subscribe_all(&mut subscribers);
    }
}

impl<'a, 'm> ProcessLifetimeHook for Dispatcher<'a, 'm> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main<Stopped>,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.subscribers
            .read()
            .process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_main_init(main, context))
    }

    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main<Stopped>,
        exit_reason: &ExitReason,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.subscribers
            .read()
            .process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_main_fini(main, exit_reason, context))
    }

    fn handle_checker_init<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker<Stopped>,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.subscribers
            .read()
            .process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_checker_init(checker, context))
    }

    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker<Stopped>,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.subscribers
            .read()
            .process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_checker_fini(checker, context))
    }

    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.subscribers
            .read()
            .process_lifetime_hooks
            .iter()
            .try_for_each(|h| h.handle_all_fini(context))
    }
}

impl<'a, 'm> StandardSyscallHandler for Dispatcher<'a, 'm> {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.subscribers.read().standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_entry(
                syscall,
                hctx(context.child, context.check_coord, context.scope),
            )?;

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
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.subscribers.read().standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit(
                ret_val,
                syscall,
                hctx(context.child, context.check_coord, context.scope),
            )?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        context: HandlerContext<Stopped>,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        for handler in &self.subscribers.read().standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_entry_main(
                syscall,
                hctx(context.child, context.check_coord, context.scope),
            )?;

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
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.subscribers.read().standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit_main(
                ret_val,
                saved_incomplete_syscall,
                hctx(context.child, context.check_coord, context.scope),
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
        context: HandlerContext<Stopped>,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        for handler in &self.subscribers.read().standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_entry_checker(
                syscall,
                hctx(context.child, context.check_coord, context.scope),
            )?;

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
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.subscribers.read().standard_syscall_handlers {
            let ret = handler.handle_standard_syscall_exit_checker(
                ret_val,
                saved_syscall,
                hctx(context.child, context.check_coord, context.scope),
            )?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a, 'm> CustomSyscallHandler for Dispatcher<'a, 'm> {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.subscribers.read().custom_syscall_handlers {
            let ret = handler.handle_custom_syscall_entry(
                sysno,
                args,
                hctx(context.child, context.check_coord, context.scope),
            )?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: HandlerContext<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        for handler in &self.subscribers.read().custom_syscall_handlers {
            let ret = handler.handle_custom_syscall_exit(
                ret_val,
                hctx(context.child, context.check_coord, context.scope),
            )?;

            if !matches!(ret, SyscallHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl<'a, 'm> SignalHandler for Dispatcher<'a, 'm> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        for handler in &self.subscribers.read().signal_handlers {
            let ret = handler.handle_signal(
                signal,
                hctx(context.child, context.check_coord, context.scope),
            )?;

            if !matches!(ret, SignalHandlerExitAction::NextHandler) {
                return Ok(ret);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl SegmentEventHandler for Dispatcher<'_, '_> {
    generate_event_handler!(segment_event_handlers, fn handle_checkpoint_created_pre(&self, main: &mut Main<Stopped>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_created(&self, main: &mut Main<Running>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_chain_closed(&self, main: &mut Main<Running>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_filled(&self, main: &mut Main<Running>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_ready(&self, checker: &mut Checker<Stopped>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_completed(&self, checker: &mut Checker<Stopped>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_checked(&self, checker: &mut Checker<Stopped>, check_fail_reason: &Option<CheckFailReason>));
    generate_event_handler!(segment_event_handlers, fn handle_segment_removed(&self, segment: &Arc<Segment>));
}

impl<'a, 'm> IgnoredPagesProvider for Dispatcher<'a, 'm> {
    fn get_ignored_pages(&self) -> Box<[usize]> {
        let mut pages = Vec::new();

        for provider in &self.subscribers.read().ignored_pages_providers {
            pages.append(&mut provider.get_ignored_pages().into_vec());
        }

        pages.into_boxed_slice()
    }
}

impl<'a, 'm> ScheduleCheckpoint for Dispatcher<'a, 'm> {
    generate_event_handler!(schedule_checkpoint, fn schedule_checkpoint(&self, main: &mut Main<Stopped>, check_coord: &CheckCoordinator));
}

impl<'a, 'm> ScheduleCheckpointReady for Dispatcher<'a, 'm> {
    generate_event_handler!(schedule_checkpoint_ready_handlers, fn handle_ready_to_schedule_checkpoint(&self, check_coord: &CheckCoordinator));
}

impl<'a, 'm> DirtyPageAddressTracker for Dispatcher<'a, 'm> {
    generate_event_handler_option!(dirty_page_tracker,
        fn take_dirty_pages_addresses<'b>(
            &self,
            inferior_id: InferiorId,
            extra_writable_ranges: &[Range<usize>],
        ) -> Result<DirtyPageAddressesWithFlags>
    );

    generate_event_handler_option!(dirty_page_tracker,
        fn nr_dirty_pages<'b>(
            &self,
            inferior_id: InferiorId,
        ) -> Result<usize>
    );
}

impl<'a, 'm> ExtraWritableRangesProvider for Dispatcher<'a, 'm> {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]> {
        let mut ranges = Vec::new();

        for provider in &self.subscribers.read().extra_writable_ranges_providers {
            ranges.append(&mut provider.get_extra_writable_ranges().into_vec());
        }

        ranges.into_boxed_slice()
    }
}

impl StatisticsProvider for Dispatcher<'_, '_> {
    fn class_name(&self) -> &'static str {
        "combined"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        self.subscribers
            .read()
            .stats_providers
            .iter()
            .flat_map(|ss| {
                ss.statistics()
                    .into_vec()
                    .into_iter()
                    .map(|(stat_name, value)| (format!("{}.{}", ss.class_name(), stat_name), value))
            })
            .collect()
    }
}

impl RegisterComparator for Dispatcher<'_, '_> {
    fn compare_registers(
        &self,
        chk_registers: &mut Registers,
        ref_registers: &mut Registers,
    ) -> Result<RegisterComparsionResult> {
        for comparator in &self.subscribers.read().register_comparators {
            let result = comparator.compare_registers(chk_registers, ref_registers)?;

            if result != RegisterComparsionResult::NoResult {
                return Ok(result);
            }
        }

        Ok(RegisterComparsionResult::NoResult)
    }
}

impl MemoryComparator for Dispatcher<'_, '_> {
    fn compare_memory(
        &self,
        page_addresses: &[Range<usize>],
        chk_process: Process<Stopped>,
        ref_process: Process<Stopped>,
    ) -> Result<(Process<Stopped>, Process<Stopped>, MemoryComparsionResult)> {
        if let Some(c) = self.subscribers.read().memory_comparators.first() {
            c.compare_memory(page_addresses, chk_process, ref_process)
        } else {
            Ok((chk_process, ref_process, MemoryComparsionResult::Pass))
        }
    }
}

impl ModuleLifetimeHook for Dispatcher<'_, '_> {
    fn init<'s, 'scope, 'env>(&'s self, scope: &'scope Scope<'scope, 'env>) -> Result<()>
    where
        's: 'scope,
    {
        self.subscribers
            .read()
            .module_lifetime_hooks
            .iter()
            .try_for_each(|m| m.init(scope))
    }

    fn fini<'s, 'scope, 'env>(&'s self, scope: &'scope Scope<'scope, 'env>) -> Result<()>
    where
        's: 'scope,
    {
        self.subscribers
            .read()
            .module_lifetime_hooks
            .iter()
            .try_for_each(|m| m.fini(scope))
    }
}

pub trait Module: Sync {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd;
}

impl ExecutionPointProvider for Dispatcher<'_, '_> {
    generate_event_handler_option!(exec_point_provider,
        fn get_current_execution_point<'b>(
            &self,
            child: &mut InferiorRefMut<Stopped>,
        ) -> Result<Arc<dyn ExecutionPoint>>
    );
}

impl MemoryEventHandler for Dispatcher<'_, '_> {
    fn handle_memory_map_created(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        for handler in &self.subscribers.read().memory_event_handlers {
            handler.handle_memory_map_created(map, hctx(ctx.child, ctx.check_coord, ctx.scope))?;
        }

        Ok(())
    }

    fn handle_memory_map_removed(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        for handler in &self.subscribers.read().memory_event_handlers {
            handler.handle_memory_map_removed(map, hctx(ctx.child, ctx.check_coord, ctx.scope))?;
        }

        Ok(())
    }

    fn handle_memory_map_updated(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        for handler in &self.subscribers.read().memory_event_handlers {
            handler.handle_memory_map_updated(map, hctx(ctx.child, ctx.check_coord, ctx.scope))?;
        }

        Ok(())
    }
}

impl InstructionPatchingEventHandler for Dispatcher<'_, '_> {
    fn handle_instruction_patched(
        &self,
        patch: &Patch,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        for handler in &self.subscribers.read().instruction_patching_events_handlers {
            handler
                .handle_instruction_patched(patch, hctx(ctx.child, ctx.check_coord, ctx.scope))?;
        }

        Ok(())
    }

    fn should_instruction_patched(&self, patch: &Patch, ctx: HandlerContext<Stopped>) -> bool {
        self.subscribers
            .read()
            .instruction_patching_events_handlers
            .iter()
            .any(|h| {
                h.should_instruction_patched(patch, hctx(ctx.child, ctx.check_coord, ctx.scope))
            })
    }

    fn handle_instruction_patch_removed(
        &self,
        patch: &Patch,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        for handler in &self.subscribers.read().instruction_patching_events_handlers {
            handler.handle_instruction_patch_removed(
                patch,
                hctx(ctx.child, ctx.check_coord, ctx.scope),
            )?;
        }

        Ok(())
    }
}

impl MigrationHandler for Dispatcher<'_, '_> {
    fn handle_checker_migration(&self, ctx: HandlerContext<Stopped>) -> Result<()> {
        for handler in &self.subscribers.read().migration_handlers {
            handler.handle_checker_migration(hctx(ctx.child, ctx.check_coord, ctx.scope))?;
        }

        Ok(())
    }
}

unsafe impl Sync for Dispatcher<'_, '_> {}
