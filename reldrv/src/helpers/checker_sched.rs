use std::{collections::BTreeSet, sync::Arc};

use log::{debug, info};
use nix::sys::signal::Signal;
use parking_lot::{Condvar, Mutex};

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        migration::MigrationHandler,
        process_lifetime::HandlerContext,
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::state::{Running, Stopped},
    types::{
        checker::{CheckFailReason, CheckerStatus},
        process_id::{Checker, Main},
        segment::Segment,
    },
};

pub struct CheckerScheduler<'a> {
    checker_cpu_set: &'a [usize],
    checker_emerg_cpu_set: &'a [usize],
    allow_checker_migration: bool,
    live_checkers: Mutex<BTreeSet<Arc<Segment>>>,
    cvar: Condvar,
}

impl<'a> CheckerScheduler<'a> {
    const SIGVAL_MIGRATE_CHECKER: usize = 0xc24be7956574a300;

    pub fn new(
        checker_cpu_set: &'a [usize],
        checker_emerg_cpu_set: &'a [usize],
        allow_checker_migration: bool,
    ) -> Self {
        Self {
            checker_cpu_set,
            checker_emerg_cpu_set,
            allow_checker_migration,
            live_checkers: Mutex::new(BTreeSet::new()),
            cvar: Condvar::new(),
        }
    }
}

impl SegmentEventHandler for CheckerScheduler<'_> {
    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        let mut live_checkers = self.live_checkers.lock();
        live_checkers.insert(main.segment.as_ref().unwrap().clone());
        Ok(())
    }

    fn handle_segment_ready(
        &self,
        checker: &mut Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> crate::error::Result<()> {
        if checker.segment.checker_status.lock().cpu_set().unwrap() != self.checker_cpu_set {
            return Ok(());
        }

        let mut live_checkers = self.live_checkers.lock();

        let mut printed = false;

        loop {
            if live_checkers
                .iter()
                .filter(|x| {
                    x.nr < checker.segment.nr
                        && x.checker_status.lock().cpu_set() == Some(self.checker_cpu_set)
                })
                .count()
                < self.checker_cpu_set.len()
            {
                break;
            }

            if self.allow_checker_migration
                && live_checkers
                    .iter()
                    .filter(|x| {
                        x.nr < checker.segment.nr
                            && x.checker_status.lock().cpu_set() == Some(self.checker_emerg_cpu_set)
                    })
                    .count()
                    < self.checker_emerg_cpu_set.len()
            {
                info!("{} Migrating to emergency CPU set", checker);
                if let Some(segment) = live_checkers.iter().find(|x| {
                    x.nr < checker.segment.nr
                        && x.checker_status.lock().cpu_set() == Some(self.checker_cpu_set)
                }) {
                    info!("{} Candidate segment: {}", checker, segment.nr);
                    let mut checker_status = segment.checker_status.lock();

                    match &mut *checker_status {
                        CheckerStatus::Executing { process, cpu_set } => {
                            *cpu_set = self.checker_emerg_cpu_set.to_vec();
                            process.sigqueue(Self::SIGVAL_MIGRATE_CHECKER)?;
                        }
                        _ => (),
                    }
                }
            }

            if !printed {
                debug!("{} Throttling due to too many checkers running", checker);
                printed = true;
            }

            self.cvar.wait(&mut live_checkers);
        }

        Ok(())
    }

    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
        _check_fail_reason: &Option<CheckFailReason>,
    ) -> Result<()> {
        self.live_checkers.lock().remove(&checker.segment);
        self.cvar.notify_all();
        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        self.live_checkers.lock().remove(segment);
        self.cvar.notify_all();
        Ok(())
    }
}

impl MigrationHandler for CheckerScheduler<'_> {
    fn handle_checker_migration(&self, _ctx: HandlerContextWithInferior<Stopped>) -> Result<()> {
        self.cvar.notify_all();
        Ok(())
    }
}

impl SignalHandler for CheckerScheduler<'_> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP
            || context.process().get_sigval()? != Some(Self::SIGVAL_MIGRATE_CHECKER)
            || !context.child.is_checker()
        {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        context.check_coord.migrate_checker(
            self.checker_emerg_cpu_set.to_vec(),
            context.child.unwrap_checker_mut(),
            context.scope,
        )?;

        Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step: false })
    }
}

impl Module for CheckerScheduler<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_migration_handler(self);
        subs.install_signal_handler(self);
    }
}
