use std::{collections::BTreeSet, sync::Arc};

use log::{debug, info};
use nix::sys::signal::Signal;
use parking_lot::{Condvar, Mutex};

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        migration::MigrationHandler,
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::state::{Running, Stopped},
    types::{
        checker::{CheckFailReason, CheckerStatus},
        exit_reason::ExitReason,
        process_id::{Checker, Main},
        segment::Segment,
    },
};

struct State {
    live_checkers: BTreeSet<Arc<Segment>>,
    main_finished: bool,
}

impl State {
    fn new() -> Self {
        Self {
            live_checkers: BTreeSet::new(),
            main_finished: false,
        }
    }
}

pub struct CheckerScheduler<'a> {
    checker_cpu_set: &'a [usize],
    checker_emerg_cpu_set: &'a [usize],
    checker_booster_cpu_set: &'a [usize],

    allow_checker_migration_to_emerg: bool,
    allow_checker_migration_to_booster: bool, // allow checkers to migrate to booster CPU set after the main finishes

    state: Mutex<State>,

    cvar: Condvar,
}

impl<'a> CheckerScheduler<'a> {
    const SIGVAL_MIGRATE_CHECKER: usize = 0xc24be7956574a300;

    pub fn new(
        checker_cpu_set: &'a [usize],
        checker_emerg_cpu_set: &'a [usize],
        checker_booster_cpu_set: &'a [usize],
        allow_checker_migration_to_emerg: bool,
        allow_checker_migration_to_booster: bool,
    ) -> Self {
        Self {
            checker_cpu_set,
            checker_emerg_cpu_set,
            checker_booster_cpu_set,
            allow_checker_migration_to_emerg,
            allow_checker_migration_to_booster,
            state: Mutex::new(State::new()),
            cvar: Condvar::new(),
        }
    }

    fn migrate_checker_to_booster_if_needed(&self) -> Result<()> {
        let state = self.state.lock();

        if !state.main_finished || !self.allow_checker_migration_to_booster {
            return Ok(());
        }

        for segment in state
            .live_checkers
            .iter()
            .rev()
            .take(self.checker_booster_cpu_set.len())
        {
            let mut checker_status = segment.checker_status.lock();

            if let Some(cpu_set) = checker_status.cpu_set() {
                if cpu_set == self.checker_booster_cpu_set {
                    continue;
                }

                info!("{} Migrating to booster CPU set", segment);
                match &mut *checker_status {
                    CheckerStatus::Executing { process, cpu_set } => {
                        *cpu_set = self.checker_booster_cpu_set.to_vec();
                        process.sigqueue(Self::SIGVAL_MIGRATE_CHECKER)?;
                    }
                    _ => (),
                }
            }
        }

        Ok(())
    }
}

impl SegmentEventHandler for CheckerScheduler<'_> {
    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        let mut state = self.state.lock();
        state
            .live_checkers
            .insert(main.segment.as_ref().unwrap().clone());
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

        let mut state = self.state.lock();
        let mut printed = false;

        loop {
            if state
                .live_checkers
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

            if self.allow_checker_migration_to_emerg
                && !state.main_finished
                && state
                    .live_checkers
                    .iter()
                    .filter(|x| {
                        x.nr < checker.segment.nr
                            && x.checker_status.lock().cpu_set() == Some(self.checker_emerg_cpu_set)
                    })
                    .count()
                    < self.checker_emerg_cpu_set.len()
            {
                info!("{} Migrating oldest checker to emergency CPU set", checker);

                if let Some(segment) = state.live_checkers.iter().find(|x| {
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

            self.cvar.wait(&mut state);
        }

        Ok(())
    }

    fn handle_segment_checked(
        &self,
        checker: &mut Checker<Stopped>,
        _check_fail_reason: &Option<CheckFailReason>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        self.state.lock().live_checkers.remove(&checker.segment);
        self.migrate_checker_to_booster_if_needed()?;
        self.cvar.notify_all();
        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        self.state.lock().live_checkers.remove(segment);
        self.migrate_checker_to_booster_if_needed()?;
        self.cvar.notify_all();
        Ok(())
    }
}

impl ProcessLifetimeHook for CheckerScheduler<'_> {
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
        self.state.lock().main_finished = true;
        self.migrate_checker_to_booster_if_needed()?;
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
        if signal != Signal::SIGUSR1
            || context.process().get_sigval()? != Some(Self::SIGVAL_MIGRATE_CHECKER)
            || !context.child.is_checker()
        {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        let cpu_set = if self.state.lock().main_finished {
            self.checker_booster_cpu_set
        } else {
            self.checker_emerg_cpu_set
        };

        context.check_coord.migrate_checker(
            cpu_set.to_vec(),
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
        subs.install_process_lifetime_hook(self);
    }
}
