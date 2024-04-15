use std::sync::atomic::AtomicU32;

use log::info;
use nix::unistd::getpid;
use reldrv::{dispatcher::Module, events::syscall::StandardSyscallHandler, RelShellOptionsBuilder};

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

struct ExcessSyscallAfter {
    after: u32,
    count: AtomicU32,
}

impl ExcessSyscallAfter {
    pub fn new(after: u32) -> Self {
        ExcessSyscallAfter {
            after,
            count: AtomicU32::new(0),
        }
    }
}

impl StandardSyscallHandler for ExcessSyscallAfter {
    fn handle_standard_syscall_entry_checker(
        &self,
        _syscall: &reverie_syscalls::Syscall,
        _context: reldrv::events::HandlerContext,
    ) -> reldrv::error::Result<reldrv::events::syscall::StandardSyscallEntryCheckerHandlerExitAction>
    {
        if self
            .count
            .fetch_add(1, std::sync::atomic::Ordering::Relaxed)
            >= self.after
        {
            info!("Triggering excess syscall err");
            return Err(reldrv::error::Error::UnexpectedSyscall(
                reldrv::error::UnexpectedEventReason::Excess,
            ));
        }

        Ok(reldrv::events::syscall::StandardSyscallEntryCheckerHandlerExitAction::NextHandler)
    }
}

impl Module for ExcessSyscallAfter {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut reldrv::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
    }
}

#[test]
fn excess_syscall_on_1st() {
    trace_w_options(
        || {
            checkpoint_take();
            getpid();
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .extra_modules(vec![Box::new(ExcessSyscallAfter::new(0))])
            .build()
            .unwrap(),
    )
    .expect_panic()
}
