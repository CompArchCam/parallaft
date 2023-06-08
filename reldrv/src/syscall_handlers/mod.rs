pub mod clone;
pub mod execve;
pub mod rseq;

use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    check_coord::CheckCoordinator,
    process::Process,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    segments::Segment,
};

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
    /// Called when the main process enters a standard syscall.
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> StandardSyscallEntryMainHandlerExitAction {
        StandardSyscallEntryMainHandlerExitAction::NextHandler
    }

    /// Called when the main process exits from a standard syscall.
    /// Only called if the `saved_incomplete_syscall.exit_action` is set to `Custom`.
    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        SyscallHandlerExitAction::NextHandler
    }

    /// Called when a checker process enters a standard syscall.
    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> StandardSyscallEntryCheckerHandlerExitAction {
        StandardSyscallEntryCheckerHandlerExitAction::NextHandler
    }

    /// Called when a checker process exits from a standard syscall.
    /// Only called if the `saved_syscall.exit_action` is set to `Custom`.
    fn handle_standard_syscall_exit_checker(
        &self,
        ret_val: isize,
        saved_syscall: &SavedSyscall,
        active_segment: &mut Segment,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        SyscallHandlerExitAction::NextHandler
    }

    /// Called when any process enters a standard syscall.
    /// Called before `handle_standard_syscall_entry_{main,checker}` if in protected region.
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        SyscallHandlerExitAction::NextHandler
    }

    /// Called when any process exits from a standard syscall.
    /// Called before `handle_standard_syscall_exit_{main,checker}` if in protected region.
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        SyscallHandlerExitAction::NextHandler
    }
}

#[allow(unused_variables)]
pub trait CustomSyscallHandler {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        SyscallHandlerExitAction::NextHandler
    }

    fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        SyscallHandlerExitAction::NextHandler
    }
}

#[allow(unused_variables)]
pub trait MainInitHandler {
    fn handle_main_init(&self, process: &Process) {}
}
