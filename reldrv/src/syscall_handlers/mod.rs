pub mod clone;
pub mod execve;
pub mod exit;
pub mod mmap;
pub mod record_replay;
pub mod replicate;
pub mod rseq;

use std::thread::Scope;

use reverie_syscalls::Syscall;
use syscalls::SyscallArgs;

use crate::{
    check_coord::{CheckCoordinator, ProcessIdentityRef, UpgradableReadGuard},
    error::Result,
    process::Process,
    saved_syscall::{SavedIncompleteSyscall, SavedSyscall},
    segments::Segment,
};

pub const SYSNO_CHECKPOINT_TAKE: usize = 0xff77;
pub const SYSNO_CHECKPOINT_FINI: usize = 0xff78;
pub const SYSNO_CHECKPOINT_SYNC: usize = 0xff79;
pub const CUSTOM_SYSNO_START: usize = 0xff7a;

pub struct HandlerContext<'id, 'process, 'disp, 'scope, 'env, 'modules> {
    pub child: &'id mut ProcessIdentityRef<'process, UpgradableReadGuard<Segment>>,
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules>,
    pub scope: &'scope Scope<'scope, 'env>,
}

impl HandlerContext<'_, '_, '_, '_, '_, '_> {
    pub fn process(&self) -> &Process {
        self.child.process().unwrap()
    }
}

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
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit_main(
        &self,
        ret_val: isize,
        saved_incomplete_syscall: &SavedIncompleteSyscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry_checker(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<StandardSyscallEntryCheckerHandlerExitAction> {
        Ok(StandardSyscallEntryCheckerHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit_checker(
        &self,
        ret_val: isize,
        saved_syscall: &SavedSyscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
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
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }

    fn handle_custom_syscall_exit(
        &self,
        ret_val: isize,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

pub fn is_execve_ok(syscall: &Syscall, ret_val: isize) -> bool {
    return matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) && ret_val == 0;
}
