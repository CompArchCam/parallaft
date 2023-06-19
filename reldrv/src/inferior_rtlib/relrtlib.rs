use log::info;
use nix::sys::{ptrace, signal::Signal};
use parking_lot::{Mutex, RwLock};
use perf_event::{Counter, SampleFlag};
use reverie_syscalls::{AddrMut, MemoryAccess};
use syscalls::SyscallArgs;

use crate::{
    dispatcher::{Dispatcher, Installable},
    process::Process,
    segments::{CheckpointCaller, Segment, SegmentEventHandler},
    signal_handlers::{SignalHandler, SignalHandlerExitAction},
    syscall_handlers::{
        CustomSyscallHandler, HandlerContext, SyscallHandlerExitAction, CUSTOM_SYSNO_START,
        SYSNO_CHECKPOINT_TAKE,
    },
};

const SYSNO_SET_COUNTER_ADDR: usize = CUSTOM_SYSNO_START + 1;

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

    pub fn get_counter(&self, process: &Process) -> Option<u64> {
        self.counter_addr
            .read()
            .map(|addr| process.read_value(addr).unwrap())
    }

    pub fn set_counter(&self, process: &Process, val: u64) -> Option<()> {
        let addr = *self.counter_addr.read().as_ref()?;

        let mut process = Process::new(process.pid);
        process
            .write_value(AddrMut::from_raw(addr).unwrap(), &val)
            .unwrap();

        Some(())
    }
}

impl SegmentEventHandler for RelRtLib {
    fn handle_segment_ready(
        &self,
        segment: &mut Segment,
        _checkpoint_end_caller: CheckpointCaller,
    ) {
        let last_checker = segment.checker().unwrap();
        let checkpoint = segment.status.checkpoint_end().unwrap();

        if checkpoint.caller == CheckpointCaller::Child {
            let counter = *self.saved_counter_value.lock();
            self.set_counter(last_checker, (-(counter as i64) - 1) as u64);
        }
    }
}

impl CustomSyscallHandler for RelRtLib {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        args: SyscallArgs,
        context: &HandlerContext,
    ) -> SyscallHandlerExitAction {
        if sysno == SYSNO_SET_COUNTER_ADDR {
            assert_eq!(context.process.pid, context.check_coord.main.pid);
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
                .observe_pid(context.process.pid.as_raw())
                .wakeup_watermark(1)
                .sample_period(self.period)
                .sample(SampleFlag::IP)
                .sigtrap(true)
                .remove_on_exec(true)
                .build()
                .unwrap();

            *self.counter_addr.write() = base_address;

            self.perf_counter.lock().insert(counter).enable().unwrap();

            return SyscallHandlerExitAction::ContinueInferior;
        } else if sysno == SYSNO_CHECKPOINT_TAKE {
            if context.process.pid == context.check_coord.main.pid {
                if let Some(c) = self.perf_counter.lock().as_mut() {
                    c.enable().unwrap();
                }
            }
        }

        SyscallHandlerExitAction::NextHandler
    }
}

impl SignalHandler for RelRtLib {
    fn handle_signal(&self, signal: Signal, context: &HandlerContext) -> SignalHandlerExitAction {
        if signal == Signal::SIGTRAP {
            let siginfo = ptrace::getsiginfo(context.process.pid).unwrap();
            if siginfo.si_code == 0x6
            /* TRAP_PERF */
            {
                info!("[PID {: >8}] Trap: Perf", context.process.pid);
                let c = self.get_counter(context.process).unwrap();
                self.set_counter(context.process, -1_i64 as u64);
                *self.saved_counter_value.lock() = c;

                self.perf_counter
                    .lock()
                    .as_mut()
                    .unwrap()
                    .disable()
                    .unwrap();

                return SignalHandlerExitAction::SuppressSignalAndContinueInferior;
            }
        }

        SignalHandlerExitAction::NextHandler
    }
}

impl<'a> Installable<'a> for RelRtLib {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_segment_event_handler(self);
        dispatcher.install_custom_syscall_handler(self);
        dispatcher.install_signal_handler(self);
    }
}
