use std::{collections::HashMap, sync::Arc};

use derivative::Derivative;
use log::info;
use nix::{sys::signal::Signal, unistd::Pid};
use parking_lot::Mutex;
use perf_event::events::Hardware;
use try_insert_ext::OptionInsertExt;

use crate::{
    dispatcher::Module,
    error::{Error, Result},
    events::{
        migration::MigrationHandler,
        process_lifetime::HandlerContext,
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::{
        siginfo::SigInfoExt,
        state::{Running, Stopped},
    },
    types::{
        perf_counter::{
            symbolic_events::{
                expr::Target, GenericHardwareEventCounter, GenericHardwareEventCounterWithInterrupt,
            },
            PerfCounter, PerfCounterWithInterrupt,
        },
        process_id::{Checker, InferiorRefMut, Main},
        segment::{Segment, SegmentId},
    },
};

#[derive(Derivative)]
#[derivative(Debug)]
struct SegmentInfo {
    id: SegmentId,
    main_insn_count: Option<u64>,
    checker_insn_count_offset: u64,
    #[derivative(Debug = "ignore")]
    checker_insn_irq: Option<GenericHardwareEventCounterWithInterrupt>,
}

impl SegmentInfo {
    fn checker_insn_count(&mut self) -> Result<u64> {
        let mut result = self.checker_insn_count_offset;
        if let Some(irq) = &mut self.checker_insn_irq {
            result += irq.read()?;
        }
        Ok(result)
    }

    fn reset(&mut self) {
        self.checker_insn_count_offset = 0;
        self.checker_insn_irq = None;
    }
}

#[derive(Derivative)]
#[derivative(Debug)]
pub struct CheckerTimeoutKiller<'a> {
    main_cpu_set: &'a [usize],
    segment_info_map: Mutex<HashMap<SegmentId, SegmentInfo>>,
    #[derivative(Debug = "ignore")]
    main_insn_counter: Mutex<Option<GenericHardwareEventCounter>>,
}

impl<'a> CheckerTimeoutKiller<'a> {
    const HEADROOM: f64 = 0.1;
    const SIGVAL_INIT_IRQ: usize = 0x1f6d26d2158183db;

    pub fn new(main_cpu_set: &'a [usize]) -> Self {
        Self {
            main_cpu_set,
            segment_info_map: Mutex::new(HashMap::new()),
            main_insn_counter: Mutex::new(None),
        }
    }

    fn init_or_migrate_checker_insn_irq(
        &self,
        segment_info: &mut SegmentInfo,
        pid: Pid,
        new_cpu_set: &[usize],
    ) -> Result<()> {
        let mut old_count = 0;

        if let Some(checker_insn_irq) = &mut segment_info.checker_insn_irq {
            old_count = checker_insn_irq.read()?;
        }

        segment_info.checker_insn_irq = Some(GenericHardwareEventCounterWithInterrupt::new(
            Hardware::INSTRUCTIONS,
            pid,
            true,
            new_cpu_set,
            ((segment_info.main_insn_count.unwrap() as f64) * (1.0 + Self::HEADROOM)) as u64
                - old_count,
            None,
        )?);

        Ok(())
    }
}

impl SegmentEventHandler for CheckerTimeoutKiller<'_> {
    fn handle_checkpoint_created_post_fork(
        &self,
        main: &mut Main<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut main_insn_counter = self.main_insn_counter.lock();

        let counter = main_insn_counter.get_or_try_insert_with(|| {
            GenericHardwareEventCounter::new(
                Hardware::INSTRUCTIONS,
                Target::Pid(main.process().pid),
                true,
                Some(self.main_cpu_set),
            )
        })?;

        if let Some(segment) = &main.segment {
            let mut segment_info_map = self.segment_info_map.lock();
            let segment_info = segment_info_map.get_mut(&segment.nr).unwrap();

            segment_info.main_insn_count = Some(counter.read()?);
            let checker_status = segment.checker_status.lock();
            if let Some(process) = checker_status.process() {
                process.sigqueue(Self::SIGVAL_INIT_IRQ)?;
            }
        }

        counter.reset()?;

        Ok(())
    }

    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        let segment_id = main.segment.as_ref().unwrap().nr;

        self.segment_info_map.lock().insert(
            segment_id,
            SegmentInfo {
                id: segment_id,
                main_insn_count: None,
                checker_insn_count_offset: 0,
                checker_insn_irq: None,
            },
        );
        Ok(())
    }

    fn handle_segment_completed(&self, checker: &mut Checker<Stopped>) -> Result<()> {
        self.segment_info_map
            .lock()
            .get_mut(&checker.segment.nr)
            .unwrap()
            .reset();

        Ok(())
    }

    fn handle_segment_ready(
        &self,
        checker: &mut Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut segment_info_map = self.segment_info_map.lock();

        let segment_info = segment_info_map.get_mut(&checker.segment.nr).unwrap();
        segment_info.reset();

        if segment_info.main_insn_count.is_some() {
            self.init_or_migrate_checker_insn_irq(
                segment_info,
                checker.process().pid,
                checker.segment.checker_status.lock().cpu_set().unwrap(),
            )?;
        }

        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        self.segment_info_map.lock().remove(&segment.nr);
        Ok(())
    }
}

impl SignalHandler for CheckerTimeoutKiller<'_> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        let checker = if let InferiorRefMut::Checker(checker) = context.child {
            checker
        } else {
            return Ok(SignalHandlerExitAction::NextHandler);
        };

        let siginfo = checker.process().get_siginfo()?;

        let mut segment_info_map = self.segment_info_map.lock();
        let segment_info = segment_info_map.get_mut(&checker.segment.nr).unwrap();

        if siginfo.sigval() == Some(Self::SIGVAL_INIT_IRQ) {
            if segment_info.checker_insn_count()?
                >= (segment_info.main_insn_count.unwrap() as f64 * Self::HEADROOM) as u64
            {
                info!("{checker} Timed out");
                return Err(Error::CheckerTimeout);
            }

            self.init_or_migrate_checker_insn_irq(
                segment_info,
                checker.process().pid,
                checker.segment.checker_status.lock().cpu_set().unwrap(),
            )?;

            return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                single_step: false,
            });
        } else if segment_info
            .checker_insn_irq
            .as_mut()
            .unwrap()
            .is_interrupt(&siginfo)?
        {
            info!("{checker} Timed out");
            return Err(Error::CheckerTimeout);
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl MigrationHandler for CheckerTimeoutKiller<'_> {
    fn handle_checker_migration(&self, ctx: HandlerContextWithInferior<Stopped>) -> Result<()> {
        let checker = ctx.child.unwrap_checker();

        self.init_or_migrate_checker_insn_irq(
            self.segment_info_map
                .lock()
                .get_mut(&checker.segment.nr)
                .unwrap(),
            checker.process().pid,
            checker.segment.checker_status.lock().cpu_set().unwrap(),
        )?;

        Ok(())
    }
}

impl Module for CheckerTimeoutKiller<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_signal_handler(self);
        subs.install_migration_handler(self);
    }
}
