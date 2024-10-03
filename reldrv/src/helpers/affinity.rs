use std::process::Command;

use log::info;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        migration::MigrationHandler,
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        segment::SegmentEventHandler,
        HandlerContextWithInferior,
    },
    process::{
        state::{Running, Stopped},
        Process,
    },
    types::process_id::{Checker, Main},
};

pub struct AffinitySetter<'a> {
    main_cpu_set: &'a [usize],
    checker_cpu_set: &'a [usize],
    shell_cpu_set: &'a [usize],

    #[cfg(feature = "intel_cat")]
    cache_masks: Option<(u32, u32, u32)>,
}

impl<'a> AffinitySetter<'a> {
    pub fn new(
        main_cpu_set: &'a [usize],
        checker_cpu_set: &'a [usize],
        shell_cpu_set: &'a [usize],
    ) -> Self {
        Self {
            main_cpu_set,
            checker_cpu_set,
            shell_cpu_set,
            #[cfg(feature = "intel_cat")]
            cache_masks: None,
        }
    }

    #[cfg(feature = "intel_cat")]
    pub fn new_with_cache_allocation(
        main_cpu_set: &'a [usize],
        checker_cpu_set: &'a [usize],
        shell_cpu_set: &'a [usize],
        cache_masks: Option<(u32, u32, u32)>,
    ) -> Self {
        Self {
            main_cpu_set,
            checker_cpu_set,
            shell_cpu_set,
            cache_masks,
        }
    }
}

impl SegmentEventHandler for AffinitySetter<'_> {
    fn handle_segment_filled(&self, main: &mut Main<Running>) -> Result<()> {
        main.segment
            .as_ref()
            .unwrap()
            .checkpoint_end()
            .unwrap()
            .process
            .lock()
            .as_mut()
            .unwrap()
            .set_cpu_affinity(self.checker_cpu_set)?;

        Ok(())
    }
}

impl<'a> ProcessLifetimeHook for AffinitySetter<'a> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        Process::shell().set_cpu_affinity(self.shell_cpu_set)?;

        main.process_mut().set_cpu_affinity(self.main_cpu_set)?;

        #[cfg(feature = "intel_cat")]
        if !self.main_cpu_set.is_empty()
            && !self.checker_cpu_set.is_empty()
            && !self.shell_cpu_set.is_empty()
        {
            if let Some((main_mask, checker_mask, shell_mask)) = self.cache_masks {
                let output = Command::new("pqos")
                    .arg("-e")
                    .arg(format!(
                        "llc:1=0x{:x};llc:2=0x{:x};llc:3=0x{:x}",
                        main_mask, checker_mask, shell_mask,
                    ))
                    .arg("-a")
                    .arg(format!(
                        "llc:1={};llc:2={};llc:3={}",
                        self.main_cpu_set
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                        self.checker_cpu_set
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                        self.shell_cpu_set
                            .iter()
                            .map(|x| x.to_string())
                            .collect::<Vec<_>>()
                            .join(","),
                    ))
                    .output()
                    .expect("Failed to set cache allocation");

                info!("pqos output: \n{}", String::from_utf8_lossy(&output.stdout));
                assert!(output.status.success(), "Failed to set cache allocation")
            }
        }

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
        let checker_status = checker.exec.status.lock();
        let checker_cpu_set = checker_status.cpu_set().unwrap();

        checker
            .process
            .as_mut()
            .unwrap()
            .set_cpu_affinity(checker_cpu_set)?;

        Process::shell().set_cpu_affinity(self.shell_cpu_set)?;

        checker
            .segment
            .checkpoint_start
            .process
            .lock()
            .as_mut()
            .unwrap()
            .set_cpu_affinity(checker_cpu_set)?;

        Ok(())
    }
}

impl MigrationHandler for AffinitySetter<'_> {
    fn handle_checker_migration(&self, context: HandlerContextWithInferior<Stopped>) -> Result<()> {
        let checker = context.child.unwrap_checker_mut();

        let checker_status = checker.exec.status.lock();
        let new_cpu_set = checker_status.cpu_set().unwrap();

        Process::shell().set_cpu_affinity(self.shell_cpu_set)?;
        checker
            .process
            .as_mut()
            .unwrap()
            .set_cpu_affinity(new_cpu_set)?;

        info!("{checker} New CPU set: {new_cpu_set:?}");

        Ok(())
    }
}

impl Module for AffinitySetter<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_process_lifetime_hook(self);
        subs.install_migration_handler(self);
    }
}
