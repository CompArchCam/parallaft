use std::thread::Scope;

use crate::{
    check_coord::CheckCoordinator,
    error::Result,
    types::{
        exit_reason::ExitReason,
        process_id::{Checker, Main},
    },
};

#[derive(Clone, Copy)]
pub struct ProcessLifetimeHookContext<'disp, 'scope, 'env, 'modules, 'tracer> {
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    pub scope: &'scope Scope<'scope, 'env>,
}

pub fn pctx<'disp, 'scope, 'env, 'modules, 'tracer>(
    check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    scope: &'scope Scope<'scope, 'env>,
) -> ProcessLifetimeHookContext<'disp, 'scope, 'env, 'modules, 'tracer> {
    ProcessLifetimeHookContext { check_coord, scope }
}

#[allow(unused_variables)]
pub trait ProcessLifetimeHook {
    /// Called after spawning the main process
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after main exits
    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        main: &mut Main,
        exit_reason: &ExitReason,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after spawning a checker process
    fn handle_checker_init<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called before killing a checker process
    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        checker: &mut Checker,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after all subprocesses exit
    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }
}
