use std::fmt::Debug;

use log::debug;
use nix::{sys::signal::Signal, unistd::Pid};
use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    exec_point_providers::ExecutionPointProvider,
    syscall_handlers::is_execve_ok,
    types::{
        perf_counter::{
            linux::LinuxPerfCounter,
            pmu_type::{detect_pmu_type_cached, PmuType},
            PerfCounterWithInterrupt,
        },
        process_id::InferiorRefMut,
    },
};

use super::ReferenceType;

enum State {
    Skipping(Box<dyn PerfCounterWithInterrupt + Send + Sync>),
    Normal(Box<dyn PerfCounterWithInterrupt + Send + Sync>),
}

impl Debug for State {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Skipping(_) => write!(f, "Skipping"),
            Self::Normal(_) => write!(f, "Normal"),
        }
    }
}

pub struct FixedIntervalSlicer {
    skip: Option<u64>,
    interval: u64,
    reference: ReferenceType,
    state: Mutex<Option<State>>,
    main_pmu_type: PmuType,
}

impl FixedIntervalSlicer {
    const SIGVAL_DO_CHECKPOINT: usize = 0xc0a0c43f9c093cc7;

    pub fn new(
        skip: Option<u64>,
        interval: u64,
        reference: ReferenceType,
        main_cpu_set: &[usize],
    ) -> Self {
        Self {
            skip,
            interval,
            reference,
            state: Mutex::new(None),
            main_pmu_type: detect_pmu_type_cached(*main_cpu_set.first().unwrap_or(&0)),
        }
    }

    fn get_perf_counter_interrupt(
        &self,
        interval: u64,
        pid: Pid,
    ) -> Result<Box<dyn PerfCounterWithInterrupt + Sync>> {
        Ok(Box::new(LinuxPerfCounter::interrupt_after_n_hw_events(
            self.reference.into(),
            self.main_pmu_type,
            pid,
            interval,
        )?))
    }
}

impl StandardSyscallHandler for FixedIntervalSlicer {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if is_execve_ok(syscall, ret_val) {
            assert!(context.child.is_main());

            if let Some(skip) = self.skip {
                debug!("Skipping the first {} {}", skip, self.reference);
                *self.state.lock() = Some(State::Skipping(
                    self.get_perf_counter_interrupt(skip, context.child.process().pid)?,
                ));
            } else {
                debug!(
                    "Starting automatic slicing with interval: {} {}",
                    self.interval, self.reference
                );

                context
                    .child
                    .process()
                    .sigqueue(Self::SIGVAL_DO_CHECKPOINT)?;

                *self.state.lock() = Some(State::Normal(
                    self.get_perf_counter_interrupt(self.interval, context.child.process().pid)?,
                ));
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for FixedIntervalSlicer {
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

            match state.take() {
                Some(State::Skipping(mut perf_counter)) => {
                    if !perf_counter.is_interrupt(signal, &main.process)? {
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
                    if main.process.get_sigval()? == Some(Self::SIGVAL_DO_CHECKPOINT) {
                        *state = Some(State::Normal(perf_counter));
                        return Ok(SignalHandlerExitAction::Checkpoint);
                    }

                    if !perf_counter.is_interrupt(signal, &main.process)? {
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

            if let Some(segment) = main.segment.as_ref().cloned() {
                let exec_point = context
                    .check_coord
                    .dispatcher
                    .get_current_execution_point(&mut (*main).into())?;

                debug!("{main} New execution point: {exec_point:?}");
                segment.record.push_event(exec_point, true, &segment)?;
            }

            return Ok(SignalHandlerExitAction::Checkpoint);
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl Module for FixedIntervalSlicer {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_signal_handler(self);
    }
}
