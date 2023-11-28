use log::info;
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::Result,
    process::{ProcessLifetimeHook, ProcessLifetimeHookContext},
};

/// On-demand fork enabler
pub struct OdfEnabler;

impl OdfEnabler {
    pub fn new() -> Self {
        Self {}
    }
}

impl ProcessLifetimeHook for OdfEnabler {
    fn handle_main_init(&self, context: &ProcessLifetimeHookContext) -> Result<()> {
        let ret = context.process.syscall_direct(
            Sysno::prctl,
            syscall_args!(65, 0, 0, 0, 0),
            false,
            false,
            false,
        )?;

        if ret < 0 {
            panic!(
                "Failed to initialise on-demand fork (ODF): {}. Check your kernel support.",
                ret
            );
        } else {
            info!("ODF enabled");
            Ok(())
        }
    }
}

impl<'a> Installable<'a> for OdfEnabler {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
