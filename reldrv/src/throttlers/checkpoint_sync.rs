use std::sync::atomic::AtomicBool;

use nix::errno::Errno;

use super::Throttler;
use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Module, Subscribers},
    error::Error,
    segments::SegmentChains,
    syscall_handlers::{CustomSyscallHandler, HandlerContext, SYSNO_CHECKPOINT_SYNC},
};

pub struct CheckpointSyncThrottler {
    sync_active: AtomicBool,
}

impl CheckpointSyncThrottler {
    pub fn new() -> Self {
        Self {
            sync_active: AtomicBool::new(false),
        }
    }
}

impl Throttler for CheckpointSyncThrottler {
    fn should_throttle(&self, _segments: &SegmentChains, _check_coord: &CheckCoordinator) -> bool {
        self.sync_active.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn should_unthrottle(&self, segments: &SegmentChains, _check_coord: &CheckCoordinator) -> bool {
        if segments.nr_live_segments() == 0 {
            self.sync_active
                .store(false, std::sync::atomic::Ordering::SeqCst);
            true
        } else {
            false
        }
    }
}

impl CustomSyscallHandler for CheckpointSyncThrottler {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: HandlerContext,
    ) -> crate::error::Result<crate::syscall_handlers::SyscallHandlerExitAction> {
        if sysno != SYSNO_CHECKPOINT_SYNC {
            return Ok(crate::syscall_handlers::SyscallHandlerExitAction::NextHandler);
        }

        if context.check_coord.segments.read().in_chain() {
            return Err(Error::ReturnedToUser(
                Errno::EINVAL,
                "Attempt to sync before checkpoint_fini is called".to_string(),
            ));
        }

        self.sync_active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(crate::syscall_handlers::SyscallHandlerExitAction::ContinueInferior)
    }
}

impl Module for CheckpointSyncThrottler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_throttler(self);
        subs.install_custom_syscall_handler(self);
    }
}
