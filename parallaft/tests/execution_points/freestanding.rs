use std::sync::Arc;

use log::info;
use nix::sys::signal::Signal;
use parallaft::{
    dispatcher::Module,
    error::Result,
    events::{
        exec_point::ExecutionPointEventHandler,
        module_lifetime::ModuleLifetimeHook,
        process_lifetime::HandlerContext,
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    exec_point_providers::ExecutionPointProvider,
    process::state::Stopped,
    types::{
        execution_point::{ExecutionPoint, ExecutionPointOwner},
        perf_counter::{
            symbolic_events::GenericHardwareEventCounterWithInterrupt, PerfCounterWithInterrupt,
        },
        process_id::{InferiorRefMut, Main},
    },
    RelShellOptionsBuilder,
};
use parking_lot::Mutex;
use perf_event::events::Hardware;

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

struct State {
    main_irq: Option<GenericHardwareEventCounterWithInterrupt>,
    exec_points: Vec<Arc<dyn ExecutionPoint>>,
    n_exec_point_reached: usize,
}

struct ExecPointTester {
    state: Mutex<State>,
}

impl ExecPointTester {
    fn new() -> Self {
        Self {
            state: Mutex::new(State {
                main_irq: None,
                exec_points: Vec::new(),
                n_exec_point_reached: 0,
            }),
        }
    }
}

impl SegmentEventHandler for ExecPointTester {
    fn handle_checkpoint_created_post_fork(
        &self,
        main: &mut Main<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut state = self.state.lock();

        if main.segment.is_some() {
            state.main_irq = None;
            return Ok(());
        }

        state.main_irq = Some(GenericHardwareEventCounterWithInterrupt::new(
            Hardware::INSTRUCTIONS,
            main.process().pid,
            true,
            &[0],
            1000,
            None,
        )?);

        Ok(())
    }

    fn handle_checker_exec_ready(
        &self,
        checker: &mut parallaft::types::process_id::Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        checker.segment.wait_until_main_finished()?;

        info!("{checker} Main finished. Preparing execution points");

        let state = self.state.lock();
        assert!(state.exec_points.len() > 0);
        for exec_point in &state.exec_points {
            exec_point.prepare(
                &checker.segment,
                &checker.exec,
                ExecutionPointOwner::Freestanding,
            )?;
        }

        Ok(())
    }
}

impl SignalHandler for ExecPointTester {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        let main = if let InferiorRefMut::Main(main) = context.child {
            main
        } else {
            return Ok(SignalHandlerExitAction::NextHandler);
        };

        let mut state = self.state.lock();

        if let Some(main_irq) = &state.main_irq {
            if main_irq.is_interrupt(&main.process().get_siginfo()?)? {
                let exec_point = context
                    .check_coord
                    .dispatcher
                    .get_current_execution_point(&mut (*main).into())?;
                info!("{main} Recorded execution point {:?}", exec_point);
                state.exec_points.push(exec_point);
                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                    single_step: false,
                });
            }
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl ExecutionPointEventHandler for ExecPointTester {
    fn handle_freestanding_exec_point_reached(
        &self,
        exec_point: &dyn ExecutionPoint,
        checker: &mut parallaft::types::process_id::Checker<Stopped>,
    ) -> Result<()> {
        info!("{checker} Reached execution point: {}", exec_point);
        self.state.lock().n_exec_point_reached += 1;

        Ok(())
    }
}

impl ModuleLifetimeHook for ExecPointTester {
    fn fini<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        let state = self.state.lock();
        assert_eq!(state.n_exec_point_reached, state.exec_points.len());
        assert!(state.n_exec_point_reached > 0);
        Ok(())
    }
}

impl Module for ExecPointTester {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut parallaft::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_signal_handler(self);
        subs.install_exec_point_event_handler(self);
        subs.install_module_lifetime_hook(self);
    }
}

#[test]
fn test_freestanding_exec_points() {
    trace_w_options::<()>(
        || {
            checkpoint_take();
            let mut i = 0;
            while i < 10000 {
                i += 1;
            }
            checkpoint_fini();
            Ok(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .test_with_exec_point_replay()
            .extra_modules(vec![Box::new(ExecPointTester::new())])
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}
