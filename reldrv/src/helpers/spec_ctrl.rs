use log::info;
use nix::libc;
use syscalls::{syscall_args, Sysno};

use crate::{
    dispatcher::{Module, Subscribers},
    events::process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
};

pub struct SpecCtrlSetter {
    enable_speculative_store_bypass_misfeature: bool,
    enable_indirect_branch_speculation_misfeature: bool,
}

impl SpecCtrlSetter {
    pub fn new(
        enable_speculative_store_bypass_misfeature: bool,
        enable_indirect_branch_speculation_misfeature: bool,
    ) -> Self {
        Self {
            enable_speculative_store_bypass_misfeature,
            enable_indirect_branch_speculation_misfeature,
        }
    }
}

impl ProcessLifetimeHook for SpecCtrlSetter {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> crate::error::Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        if self.enable_speculative_store_bypass_misfeature {
            let ret = context.process.syscall_direct(
                Sysno::prctl,
                syscall_args!(
                    libc::PR_SET_SPECULATION_CTRL as _,
                    libc::PR_SPEC_STORE_BYPASS as _,
                    libc::PR_SPEC_ENABLE as _
                ),
                false,
                false,
                false,
            )?;
            assert_eq!(
                ret, 0,
                "Failed to enable speculative store bypass misfeature"
            );
            info!("Speculative store bypass misfeature enabled");
        }

        if self.enable_indirect_branch_speculation_misfeature {
            let ret = context.process.syscall_direct(
                Sysno::prctl,
                syscall_args!(
                    libc::PR_SET_SPECULATION_CTRL as _,
                    libc::PR_SPEC_INDIRECT_BRANCH as _,
                    libc::PR_SPEC_ENABLE as _
                ),
                false,
                false,
                false,
            )?;
            assert_eq!(
                ret, 0,
                "Failed to enable indirect branch speculation misfeature"
            );
            info!("Indirect branch speculation misfeature enabled");
        }
        Ok(())
    }
}

impl Module for SpecCtrlSetter {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
    }
}
