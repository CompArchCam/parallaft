use log::info;
use syscalls::SyscallArgs;

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        syscall::{CustomSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    exec_point_providers::ExecutionPointProvider,
    syscall_handlers::CUSTOM_SYSNO_START,
};

/// Dump the current execution point to log on each SYSNO_DUMP_EXEC_POINT custom
/// syscall.
pub struct ExecutionPointDumper;

pub const SYSNO_DUMP_EXEC_POINT: usize = CUSTOM_SYSNO_START + 2;

impl CustomSyscallHandler for ExecutionPointDumper {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: SyscallArgs,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if sysno == SYSNO_DUMP_EXEC_POINT {
            if context.child.segment().is_some() {
                let exec_point = context
                    .check_coord
                    .dispatcher
                    .get_current_execution_point(context.child)?;
                info!("{} Current execution point: {exec_point:?}", context.child);
            }

            return Ok(SyscallHandlerExitAction::ContinueInferior);
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for ExecutionPointDumper {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_custom_syscall_handler(self);
    }
}