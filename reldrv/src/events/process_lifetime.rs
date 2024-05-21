use std::thread::Scope;

use crate::{check_coord::CheckCoordinator, error::Result, process::Process};

#[derive(Clone, Copy)]
pub struct ProcessLifetimeHookContext<'p, 'disp, 'scope, 'env, 'modules, 'tracer> {
    pub process: &'p Process,
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    pub scope: &'scope Scope<'scope, 'env>,
}

pub fn pctx<'p, 'disp, 'scope, 'env, 'modules, 'tracer>(
    process: &'p mut Process,
    check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    scope: &'scope Scope<'scope, 'env>,
) -> ProcessLifetimeHookContext<'p, 'disp, 'scope, 'env, 'modules, 'tracer> {
    ProcessLifetimeHookContext {
        process,
        check_coord,
        scope,
    }
}

#[allow(unused_variables)]
pub trait ProcessLifetimeHook {
    /// Called after spawning the main process
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after spawning a checker process
    fn handle_checker_init<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called before killing a checker process
    fn handle_checker_fini<'s, 'scope, 'disp>(
        &'s self,
        nr_dirty_pages: Option<usize>,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after all subprocesses exit
    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }

    /// Called after main exits
    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        ret_val: i32,
        context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        Ok(())
    }
}
