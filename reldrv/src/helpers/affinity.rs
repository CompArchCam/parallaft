use std::process::Command;

use log::info;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    process::Process,
    process::{ProcessLifetimeHook, ProcessLifetimeHookContext},
};

pub struct AffinitySetter<'a> {
    main_cpu_set: &'a [usize],
    checker_cpu_set: &'a [usize],
    shell_cpu_set: &'a [usize],

    #[cfg(feature = "intel_cat")]
    cache_masks: Option<(u32, u32, u32)>,
}

#[allow(unused)]
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

impl<'a> ProcessLifetimeHook for AffinitySetter<'a> {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Process::shell().set_cpu_affinity(self.shell_cpu_set)?;

        context.process.set_cpu_affinity(self.main_cpu_set)?;

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
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        context.process.set_cpu_affinity(self.checker_cpu_set)?;

        Ok(())
    }
}

impl Module for AffinitySetter<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
    }
}
