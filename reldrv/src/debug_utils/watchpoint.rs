use std::collections::HashMap;

use itertools::Itertools;
use log::{debug, info};
use nix::sys::signal::Signal;
use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        signal::{SignalHandler, SignalHandlerExitAction},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{memory::MemoryAccess, registers::RegisterAccess, state::Stopped, Process},
    syscall_handlers::is_execve_ok,
    types::{
        breakpoint::{Breakpoint, HardwareBreakpoint},
        exit_reason::ExitReason,
        process_id::{Checker, InferiorRefMut, Main},
        segment::SegmentId,
    },
};

struct WatchpointList {
    list: Vec<HardwareBreakpoint>,
    stepping_bp_pos: Option<usize>,
}

pub struct Watchpoint<'a> {
    addresses: &'a [usize],
    main_watchpoints: Mutex<Option<WatchpointList>>,
    checker_watchpoints: Mutex<HashMap<SegmentId, WatchpointList>>,
}

impl<'a> Watchpoint<'a> {
    pub fn new(addresses: &'a [usize]) -> Self {
        Self {
            addresses,
            main_watchpoints: Mutex::new(None),
            checker_watchpoints: Mutex::new(HashMap::new()),
        }
    }

    fn create_watchpoints(&self, process: &mut Process<Stopped>) -> Result<WatchpointList> {
        let mut watchpoints = Vec::new();

        for address in self.addresses {
            let mut watchpoint = HardwareBreakpoint::new(process.pid, *address, 8, true)?;
            watchpoint.enable(process)?;
            watchpoints.push(watchpoint);
        }

        Ok(WatchpointList {
            list: watchpoints,
            stepping_bp_pos: None,
        })
    }

    fn handle_if_watchpoint_hit(
        &self,
        child: &mut InferiorRefMut<Stopped>,
        watchpoints: &mut WatchpointList,
    ) -> Result<SignalHandlerExitAction> {
        if let Some(pos) = watchpoints.stepping_bp_pos {
            // handle single step hit
            let watchpoint = &mut watchpoints.list[pos];

            assert!(watchpoint.characteristics().needs_single_step_after_hit);

            if watchpoint
                .characteristics()
                .needs_bp_disabled_during_single_stepping
            {
                watchpoint.enable(child.process_mut())?;
            }

            info!(
                "{child} Watchpoint finished at address {:#0x}, new value: {:#0x}",
                watchpoint.addr(),
                child.process().read_value::<_, u64>(watchpoint.addr())?,
            );

            watchpoints.stepping_bp_pos = None;

            return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                single_step: false,
            });
        }

        let watchpoint = watchpoints
            .list
            .iter_mut()
            .find_position(|w| matches!(w.is_hit(child.process()), Ok(true)));

        if let Some((pos, watchpoint)) = watchpoint {
            info!(
                "{child} Watchpoint hit at address {:#0x}, old value: {:#0x}, ip: {:#0x}",
                watchpoint.addr(),
                child.process().read_value::<_, u64>(watchpoint.addr())?,
                child.process().read_registers()?.ip()
            );

            let single_step;

            if watchpoint.characteristics().needs_single_step_after_hit {
                single_step = true;
                watchpoints.stepping_bp_pos = Some(pos);

                if watchpoint
                    .characteristics()
                    .needs_bp_disabled_during_single_stepping
                {
                    watchpoint.disable(child.process_mut())?;
                }
            } else {
                single_step = false;
            }

            return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step });
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }

    fn register_main_watchpoints(&self, main: &mut Main<Stopped>) -> Result<()> {
        *self.main_watchpoints.lock() = Some(self.create_watchpoints(main.process_mut())?);
        debug!("{main} {} watchpoints registered", self.addresses.len());
        Ok(())
    }
}

impl ProcessLifetimeHook for Watchpoint<'_> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.register_main_watchpoints(main)?;
        Ok(())
    }

    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        _main: &mut Main<Stopped>,
        _exit_reason: &ExitReason,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        *self.main_watchpoints.lock() = None;
        Ok(())
    }

    fn handle_checker_init<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.checker_watchpoints.lock().insert(
            checker.segment.nr,
            self.create_watchpoints(checker.process_mut())?,
        );

        debug!("{checker} {} watchpoints registered", self.addresses.len());

        Ok(())
    }

    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        self.checker_watchpoints.lock().remove(&checker.segment.nr);
        Ok(())
    }
}

impl StandardSyscallHandler for Watchpoint<'_> {
    fn handle_standard_syscall_exit(
        &self,
        ret_val: isize,
        syscall: &Syscall,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        if let InferiorRefMut::Main(main) = context.child {
            if is_execve_ok(syscall, ret_val) {
                self.register_main_watchpoints(main)?;
            }
        }

        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl SignalHandler for Watchpoint<'_> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        match context.child {
            InferiorRefMut::Main(main) => {
                let mut main_watchpoints = self.main_watchpoints.lock();

                self.handle_if_watchpoint_hit(
                    &mut (*main).into(),
                    main_watchpoints.as_mut().unwrap(),
                )
            }
            InferiorRefMut::Checker(checker) => {
                let mut checker_watchpoints = self.checker_watchpoints.lock();
                let nr = checker.segment.nr;

                self.handle_if_watchpoint_hit(
                    &mut (*checker).into(),
                    checker_watchpoints.get_mut(&nr).unwrap(),
                )
            }
        }
    }
}

impl Module for Watchpoint<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_signal_handler(self);
        subs.install_standard_syscall_handler(self);
    }
}
