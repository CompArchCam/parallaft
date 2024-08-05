use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    events::{
        hctx,
        memory::MemoryEventHandler,
        syscall::{
            StandardSyscallEntryMainHandlerExitAction, StandardSyscallHandler,
            SyscallHandlerExitAction,
        },
        HandlerContext,
    },
    types::memory_map::MemoryMap,
};

use super::is_execve_ok;

pub struct ExecveHandler {}

impl Default for ExecveHandler {
    fn default() -> Self {
        Self::new()
    }
}

impl ExecveHandler {
    pub fn new() -> Self {
        Self {}
    }
}

impl StandardSyscallHandler for ExecveHandler {
    fn handle_standard_syscall_entry_main(
        &self,
        syscall: &Syscall,
        _context: HandlerContext,
    ) -> Result<StandardSyscallEntryMainHandlerExitAction> {
        if matches!(syscall, Syscall::Execve(_) | Syscall::Execveat(_)) {
            return Err(Error::NotSupported(
                "Execve(at) is disallowed in protected regions".to_string(),
            ));
        }

        Ok(StandardSyscallEntryMainHandlerExitAction::NextHandler)
    }

    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            context.check_coord.dispatcher.handle_memory_map_removed(
                &MemoryMap::all(),
                hctx(context.child, context.check_coord, context.scope),
            )?;

            for map in context.process().procfs()?.maps()? {
                context.check_coord.dispatcher.handle_memory_map_created(
                    &map.into(),
                    hctx(context.child, context.check_coord, context.scope),
                )?;
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for ExecveHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}
