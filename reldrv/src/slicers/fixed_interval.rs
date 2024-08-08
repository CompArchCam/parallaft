use std::fmt::Debug;

use log::debug;
use nix::{sys::signal::Signal, unistd::Pid};
use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result},
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{CustomSyscallHandler, StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    process::Process,
    signal_handlers::begin_protection::main_begin_protection_req,
    syscall_handlers::is_execve_ok,
    types::{
        custom_sysno::CustomSysno,
        perf_counter::{
            symbolic_events::GenericHardwareEventCounterWithInterrupt, PerfCounter,
            PerfCounterWithInterrupt,
        },
        process_id::{InferiorRefMut, Main},
    },
};

use super::ReferenceType;

enum State {
    Skipping(GenericHardwareEventCounterWithInterrupt),
    Normal(GenericHardwareEventCounterWithInterrupt),
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skipping(_) => write!(f, "Skipping"),
            Self::Normal(_) => write!(f, "Normal"),
        }
    }
}

pub struct FixedIntervalSlicer<'a> {
    skip: Option<u64>,
    interval: u64,
    reference: ReferenceType,
    state: Mutex<Option<State>>,
    main_cpu_set: &'a [usize],
    is_test: bool,
    auto_start: bool,
}

impl<'a> FixedIntervalSlicer<'a> {
    pub fn new(
        skip: Option<u64>,
        interval: u64,
        reference: ReferenceType,
        main_cpu_set: &'a [usize],
        is_test: bool,
        auto_start: bool,
    ) -> Self {
        Self {
            skip,
            interval,
            reference,
            state: Mutex::new(None),
            main_cpu_set,
            is_test,
            auto_start,
        }
    }

    fn get_perf_counter_interrupt(
        &self,
        interval: u64,
        pid: Pid,
    ) -> Result<GenericHardwareEventCounterWithInterrupt> {
        GenericHardwareEventCounterWithInterrupt::new(
            self.reference.into(),
            pid,
            true,
            self.main_cpu_set,
            interval,
            None,
        )
    }

    fn start_if_auto(&self, process: &Process) -> Result<()> {
        if self.auto_start {
            self.start(process)?;
        }

        Ok(())
    }

    fn start(&self, process: &Process) -> Result<()> {
        let mut state = self.state.lock();
        if state.is_some() {
            debug!("Automatic slicing is already started, ignoring start request");
            return Ok(());
        }

        if let Some(skip) = self.skip {
            debug!("Skipping the first {} {}", skip, self.reference);
            *self.state.lock() = Some(State::Skipping(
                self.get_perf_counter_interrupt(skip, process.pid)?,
            ));
        } else {
            debug!(
                "Starting automatic slicing with interval: {} {}",
                self.interval, self.reference
            );

            main_begin_protection_req(process.pid)?;

            *state = Some(State::Normal(
                self.get_perf_counter_interrupt(self.interval, process.pid)?,
            ));
        }

        Ok(())
    }
}

impl StandardSyscallHandler for FixedIntervalSlicer<'_> {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            assert!(context.child.is_main());
            self.start_if_auto(context.child.process())?;
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl CustomSyscallHandler for FixedIntervalSlicer<'_> {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        match CustomSysno::from_repr(sysno) {
            Some(CustomSysno::SlicingStart) => {
                if context.child.is_main() {
                    self.start(context.child.process())?;
                }

                return Ok(SyscallHandlerExitAction::ContinueInferior);
            }
            Some(CustomSysno::CheckpointFini) => {
                if context.child.is_main() {
                    let mut state = self.state.lock();
                    match state.take() {
                        Some(State::Skipping(mut perf_counter)) => {
                            perf_counter.disable()?;
                            perf_counter.reset()?;
                        }
                        Some(State::Normal(mut perf_counter)) => {
                            perf_counter.disable()?;
                            perf_counter.reset()?;
                        }
                        None => (),
                    }
                }

                return Ok(SyscallHandlerExitAction::NextHandler);
            }
            _ => {}
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for FixedIntervalSlicer<'_> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        if let InferiorRefMut::Main(main) = context.child {
            let mut state = self.state.lock();

            let next_state;

            let sig_info = main.process.get_siginfo()?;

            match state.take() {
                Some(State::Skipping(mut perf_counter)) => {
                    if !perf_counter.is_interrupt(&sig_info)? {
                        *state = Some(State::Skipping(perf_counter));
                        return Ok(SignalHandlerExitAction::NextHandler);
                    }

                    debug!(
                        "{main} Finished skipping the first {} {}",
                        self.skip.unwrap(),
                        self.reference
                    );

                    perf_counter.disable()?;

                    next_state = State::Normal(
                        self.get_perf_counter_interrupt(self.interval, main.process.pid)?,
                    );
                }
                Some(State::Normal(mut perf_counter)) => {
                    if !perf_counter.is_interrupt(&sig_info)? {
                        *state = Some(State::Normal(perf_counter));
                        return Ok(SignalHandlerExitAction::NextHandler);
                    }

                    debug!(
                        "{main} Finished the interval of {} {}",
                        self.interval, self.reference
                    );

                    perf_counter.reset()?;
                    next_state = State::Normal(perf_counter);
                }
                None => return Ok(SignalHandlerExitAction::NextHandler),
            }

            *state = Some(next_state);

            let ret = context
                .check_coord
                .push_curr_exec_point_to_event_log(main, true);

            match ret {
                Ok(()) => return Ok(SignalHandlerExitAction::Checkpoint),
                Err(Error::InvalidState) => return Ok(SignalHandlerExitAction::ContinueInferior),
                Err(e) => return Err(e),
            };
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for FixedIntervalSlicer<'_> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main,
        _context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        if self.is_test {
            self.start_if_auto(&main.process)?;
        }

        Ok(())
    }
}

impl Module for FixedIntervalSlicer<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_signal_handler(self);
        subs.install_process_lifetime_hook(self);
        subs.install_custom_syscall_handler(self);
    }
}
