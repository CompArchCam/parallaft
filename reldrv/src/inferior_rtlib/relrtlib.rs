use log::info;
use nix::sys::{ptrace, signal::Signal};
use parking_lot::{Mutex, RwLock};
use perf_event::{Counter, SampleFlag};
use reverie_syscalls::{AddrMut, MemoryAccess};
use syscalls::SyscallArgs;

use crate::{
    check_coord::CheckCoordinator,
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    events::{
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{CustomSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    inferior_rtlib::ScheduleCheckpointReady,
    process::{dirty_pages::IgnoredPagesProvider, Process, PAGESIZE},
    syscall_handlers::{CUSTOM_SYSNO_START, SYSNO_CHECKPOINT_TAKE},
    types::{
        checkpoint::CheckpointCaller,
        segment::{Segment, SegmentEventHandler},
    },
};

use super::ScheduleCheckpoint;

pub const SYSNO_SET_COUNTER_ADDR: usize = CUSTOM_SYSNO_START + 1;

pub struct RelRtLib {
    period: u64,
    counter_addr: RwLock<Option<usize>>,
    perf_counter: Mutex<Option<Counter>>,
    saved_counter_value: Mutex<u64>,
}

impl RelRtLib {
    pub fn new(period: u64) -> Self {
        Self {
            period,
            counter_addr: RwLock::new(None),
            perf_counter: Mutex::new(None),
            saved_counter_value: Mutex::new(0),
        }
    }

    pub fn get_counter(&self, process: &Process) -> Result<u64> {
        let ret = self
            .counter_addr
            .read()
            .ok_or(Error::InvalidState)
            .map(|addr| process.read_value::<usize, u64>(addr))??;

        Ok(ret)
    }

    pub fn set_counter(&self, process: &Process, val: u64) -> Result<()> {
        let addr = *self
            .counter_addr
            .read()
            .as_ref()
            .ok_or(Error::InvalidState)?;

        let mut process = Process::new(process.pid);
        process.write_value(AddrMut::from_raw(addr).unwrap(), &val)?;

        Ok(())
    }
}

impl SegmentEventHandler for RelRtLib {
    fn handle_segment_ready(&self, segment: &mut Segment) -> Result<()> {
        let last_checker = segment.checker.process().unwrap();
        let checkpoint = segment.status.checkpoint_end().unwrap();

        if checkpoint.caller == CheckpointCaller::Child {
            let counter = *self.saved_counter_value.lock();
            self.set_counter(last_checker, (-(counter as i64) - 1) as u64)
                .ok();
        }

        Ok(())
    }
}

impl CustomSyscallHandler for RelRtLib {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if sysno == SYSNO_SET_COUNTER_ADDR {
            assert!(context.child.is_main()); // TODO: handle this more gracefully
            assert!(self.perf_counter.lock().is_none());

            let base_address = if args.arg0 == 0 {
                None
            } else {
                Some(args.arg0)
            };

            info!(
                "Set counter address {:?} requested",
                base_address.map(|p| p as *const u8)
            );

            let counter = perf_event::Builder::new(perf_event::events::Hardware::INSTRUCTIONS)
                .observe_pid(context.process().pid.as_raw())
                .wakeup_watermark(1)
                .sample_period(self.period)
                .sample(SampleFlag::IP)
                .sigtrap(true)
                .remove_on_exec(true)
                .build()?;

            *self.counter_addr.write() = base_address;

            self.perf_counter.lock().insert(counter).enable().unwrap();

            context
                .check_coord
                .dispatcher
                .handle_ready_to_schedule_checkpoint(context.check_coord)?;

            return Ok(SyscallHandlerExitAction::ContinueInferior);
        } else if sysno == SYSNO_CHECKPOINT_TAKE {
            if context.child.is_main() {
                if let Some(c) = self.perf_counter.lock().as_mut() {
                    c.enable()?;
                }
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for RelRtLib {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        let _process = context.process();

        if signal == Signal::SIGTRAP {
            let siginfo = ptrace::getsiginfo(context.process().pid)?;
            if siginfo.si_code == 0x6
            /* TRAP_PERF */
            {
                info!("{} Trap: Perf", context.child);
                self.schedule_checkpoint(context.check_coord).unwrap();
                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior);
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ScheduleCheckpoint for RelRtLib {
    fn schedule_checkpoint(&self, check_coord: &CheckCoordinator) -> Result<()> {
        let addr = self.counter_addr.read();

        if addr.is_none() {
            return Err(Error::InvalidState);
        }

        let process = &check_coord.main;

        let c = self.get_counter(&process)?;
        self.set_counter(&process, -1_i64 as u64)?;
        *self.saved_counter_value.lock() = c;

        self.perf_counter.lock().as_mut().unwrap().disable()?;

        Ok(())
    }
}

impl IgnoredPagesProvider for RelRtLib {
    fn get_ignored_pages(&self) -> Box<[usize]> {
        self.counter_addr
            .read()
            .map(|addr| vec![addr & (!((*PAGESIZE - 1) as usize))])
            .unwrap_or(vec![])
            .into_boxed_slice()
    }
}

impl Module for RelRtLib {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_custom_syscall_handler(self);
        subs.install_signal_handler(self);
        subs.install_schedule_checkpoint(self);
        subs.install_ignored_pages_provider(self);
    }
}
