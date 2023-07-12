pub mod clone;
pub mod execve;
pub mod exit;
pub mod replicate;
pub mod rseq;

use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    check_coord::CheckCoordinator,
    error::Result,
    process::Process,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    segments::Segment,
};

pub const SYSNO_CHECKPOINT_TAKE: usize = 0xff77;
pub const SYSNO_CHECKPOINT_FINI: usize = 0xff78;
pub const CUSTOM_SYSNO_START: usize = 0xff7a;

pub struct HandlerContext<'a, 'b, 'c> {
    pub process: &'a Process,
    // active_segment: Option<&'a mut Segment>,
    // is_main: bool,
    pub check_coord: &'b CheckCoordinator<'c>,
}

#[allow(unused)]
/// Action to take by the check coordinator after `handle_standard_syscall_entry_main` is called for a standard syscall.
pub enum StandardSyscallEntryMainHandlerExitAction {
    /// Try the next handler. The syscall is not handled by the current handler.
    NextHandler,

    /// Store the incomplete syscall in `active_segment.ongoing_syscall`.
    StoreSyscall(SavedIncompleteSyscall),

    /// Store the incomplete syscall in `active_segment.ongoing_syscall` and call checkpoint finalization.
    StoreSyscallAndCheckpoint(SavedIncompleteSyscall),
}

#[allow(unused)]
/// Action to take by by the check coordinator after `handle_standard_syscall_entry_checker` is called for a standard syscall.
pub enum StandardSyscallEntryCheckerHandlerExitAction {
    /// Try the next handler. The syscall is not handled by the current handler.
    NextHandler,

    /// Continue the inferior on handler exit, without trying the next handler.
    ContinueInferior,

    /// Take a finalizing checkpoint.
    Checkpoint,
}

pub enum SyscallHandlerExitAction {
    /// Try the next handler. The syscall is not handled by the current handler.
    NextHandler,

    /// Continue the inferior on handler exit, without trying the next handler.
    ContinueInferior,
}

#[allow(unused_variables)]
pub trait StandardSyscallHandler {
    /// Called when the main process enters a standard syscall AND is in a protected region.
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler)
    }

    /// Called when the main process exits from a standard syscall AND is in a protected region.
    /// Only called if the `saved_incomplete_syscall.exit_action` is set to `Custom`.
    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    /// Called when a checker process enters a standard syscall.
    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        Ok(StandardSyscallEntryCheckerHandlerExitAction::NextHandler)
    }

    /// Called when a checker process exits from a standard syscall.
    /// Only called if the `saved_syscall.exit_action` is set to `Custom`.
    fn handle_standard_syscall_exit_checker(
        &self,
        ret_val: isize,
        saved_syscall: &SavedSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    /// Called when any process enters a standard syscall.
    /// Called before `handle_standard_syscall_entry_{main,checker}` if in protected region.
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    /// Called when any process exits from a standard syscall.
    /// Called before `handle_standard_syscall_exit_{main,checker}` if in protected region.
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

#[allow(unused_variables)]
pub trait CustomSyscallHandler {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

#[allow(unused_variables)]
pub trait ProcessLifetimeHook {
    /// Called after spawning the main process
    fn handle_main_init(&self, process: &Process) {}

    /// Called after spawning a checker process
    fn handle_checker_init(&self, process: &Process) {}

    // /// Called before killing a checker process
    // fn handle_checker_fini(&self, process: &Process) {}

    /// Called after all subprocesses exit
    fn handle_all_fini(&self) {}

    /// Called after main exits
    fn handle_main_fini(&self, ret_val: i32) {}
}
