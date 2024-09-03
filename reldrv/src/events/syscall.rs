use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    error::Result,
    process::state::Stopped,
    types::segment_record::saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
};

use super::HandlerContextWithInferior;

#[derive(Debug)]
/// Action to take by the check coordinator after `handle_standard_syscall_entry_main` is called for a standard syscall.
pub enum StandardSyscallEntryMainHandlerExitAction {
    /// Try the next handler. The syscall is not handled by the current handler.
    NextHandler,

    /// Store the incomplete syscall in `active_segment.replay.ongoing_syscall`.
    StoreSyscall(SavedIncompleteSyscall),

    /// Store the incomplete syscall in `active_segment.replay.ongoing_syscall` and call checkpoint finalization.
    StoreSyscallAndCheckpoint(SavedIncompleteSyscall),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
/// Action to take by by the check coordinator after `handle_standard_syscall_entry_checker` is called for a standard syscall.
pub enum StandardSyscallEntryCheckerHandlerExitAction {
    /// Try the next handler. The syscall is not handled by the current handler.
    NextHandler,

    /// Continue the inferior on handler exit, without trying the next handler.
    ContinueInferior,

    /// Take a finalizing checkpoint.
    Checkpoint,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum SyscallHandlerExitAction {
    /// Try the next handler. The syscall is not handled by the current handler.
    NextHandler,

    /// Continue the inferior on handler exit, without trying the next handler.
    ContinueInferior,
}

#[allow(unused_variables)]
pub trait StandardSyscallHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        Ok(StandardSyscallEntryCheckerHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit_checker(
        &self,
        ret_val: isize,
        saved_syscall: &SavedSyscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
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
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}
