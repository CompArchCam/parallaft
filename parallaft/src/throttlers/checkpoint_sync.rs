use std::sync::atomic::AtomicBool;

use nix::errno::Errno;

use super::Throttler;
use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Module, Subscribers},
    error::Error,
    events::{
        syscall::{CustomSyscallHandler, SyscallHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::state::{Running, Stopped},
    types::{chains::SegmentChains, custom_sysno::CustomSysno, process_id::Main},
};

pub struct CheckpointSyncThrottler {
    sync_active: AtomicBool,
}

impl Default for CheckpointSyncThrottler {
    fn default() -> Self {
        Self::new()
    }
}

impl CheckpointSyncThrottler {
    pub fn new() -> Self {
        Self {
            sync_active: AtomicBool::new(false),
        }
    }
}

impl Throttler for CheckpointSyncThrottler {
    fn should_throttle(
        &self,
        _main: &mut Main<Stopped>,
        _segments: &SegmentChains,
        _check_coord: &CheckCoordinator,
    ) -> bool {
        self.sync_active.load(std::sync::atomic::Ordering::SeqCst)
    }

    fn should_unthrottle(
        &self,
        _main: &mut Main<Running>,
        segments: &SegmentChains,
        _check_coord: &CheckCoordinator,
    ) -> bool {
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
        context: HandlerContextWithInferior<Stopped>,
    ) -> crate::error::Result<SyscallHandlerExitAction> {
        if CustomSysno::from_repr(sysno) != Some(CustomSysno::CheckpointSync) {
            return Ok(SyscallHandlerExitAction::NextHandler);
        }

        if context.check_coord.segments.read().in_chain() {
            return Err(Error::ReturnedToUser(
                Errno::EINVAL,
                "Attempt to sync before checkpoint_fini is called".to_string(),
            ));
        }

        self.sync_active
            .store(true, std::sync::atomic::Ordering::SeqCst);
        Ok(SyscallHandlerExitAction::ContinueInferior)
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
