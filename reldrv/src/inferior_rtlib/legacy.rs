use log::info;
use parking_lot::RwLock;
use reverie_syscalls::{AddrMut, MemoryAccess};
use syscalls::SyscallArgs;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        segment::SegmentEventHandler,
        syscall::{CustomSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::{dirty_pages::IgnoredPagesProvider, Process},
    types::{checkpoint::CheckpointCaller, custom_sysno::CustomSysno, process_id::Main},
};

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub enum CliRole {
    #[default]
    Main = 0,
    Checker = 1,
    Nop = 2,
}

const MAGIC: u32 = 0xfbb59834;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CliControl {
    magic: u32,
    pub role: CliRole,
    interval_tsc: u64,
    last_tsc: u64,
    pub counter: i32,
}

pub struct LegacyInferiorRtLib {
    client_control_addr: RwLock<Option<usize>>,
}

impl Default for LegacyInferiorRtLib {
    fn default() -> Self {
        Self::new()
    }
}

impl LegacyInferiorRtLib {
    pub fn new() -> Self {
        Self {
            client_control_addr: RwLock::new(None),
        }
    }
}

impl SegmentEventHandler for LegacyInferiorRtLib {
    fn handle_segment_filled(&self, main: &mut Main) -> Result<()> {
        let segment = main.segment.as_ref().unwrap();
        // TODO: handle errors more gracefully
        let checkpoint = segment.checkpoint_end().unwrap();

        // patch the checker's client_control struct
        if let Some(base_address) = self.client_control_addr.read().as_ref() {
            let this_reference = checkpoint.process.lock();
            let mut ctl: CliControl = this_reference.read_value(*base_address).unwrap();
            drop(this_reference);

            assert_eq!(ctl.magic, MAGIC);

            ctl.role = if checkpoint.caller == CheckpointCaller::Child {
                CliRole::Checker
            } else {
                CliRole::Nop
            };

            Process::new(segment.checker_status.lock().pid().unwrap())
                .write_value(AddrMut::from_raw(*base_address).unwrap(), &ctl)
                .unwrap(); // TODO
        }

        Ok(())
    }
}

impl IgnoredPagesProvider for LegacyInferiorRtLib {
    fn get_ignored_pages(&self) -> Box<[usize]> {
        self.client_control_addr
            .read()
            .map_or(Vec::new(), |addr| vec![addr])
            .into_boxed_slice()
    }
}

impl CustomSyscallHandler for LegacyInferiorRtLib {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if CustomSysno::from_repr(sysno) == Some(CustomSysno::LegacyRtSetCliControlAddr) {
            assert!(context.child.is_main());

            let base_address = if args.arg0 == 0 {
                None
            } else {
                Some(args.arg0)
            };

            info!(
                "Set client control base address {:?} requested",
                base_address.map(|p| p as *const u8)
            );

            *self.client_control_addr.write() = base_address;

            return Ok(SyscallHandlerExitAction::ContinueInferior);
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for LegacyInferiorRtLib {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_ignored_pages_provider(self);
        subs.install_custom_syscall_handler(self);
    }
}
