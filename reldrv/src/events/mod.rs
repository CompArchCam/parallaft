pub mod comparator;
pub mod insn_patching;
pub mod memory;
pub mod migration;
pub mod module_lifetime;
pub mod process_lifetime;
pub mod segment;
pub mod signal;
pub mod syscall;

use std::thread::Scope;

use crate::{
    check_coord::CheckCoordinator,
    process::{state::ProcessState, Process},
    types::process_id::InferiorRefMut,
};

pub struct HandlerContextWithInferior<
    'ido,
    'id,
    'disp: 'scope,
    'scope,
    'env,
    'modules,
    'tracer,
    S: ProcessState,
> {
    pub child: &'ido mut InferiorRefMut<'id, S>,
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    pub scope: &'scope Scope<'scope, 'env>,
}

pub fn hctx<'ido, 'id, 'disp, 'scope, 'env, 'modules, 'tracer, S: ProcessState>(
    child: &'ido mut InferiorRefMut<'id, S>,
    check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    scope: &'scope Scope<'scope, 'env>,
) -> HandlerContextWithInferior<'ido, 'id, 'disp, 'scope, 'env, 'modules, 'tracer, S> {
    HandlerContextWithInferior {
        child,
        check_coord,
        scope,
    }
}

impl<'id, 'disp, 'scope, 'env, 'modules, 'tracer, S: ProcessState>
    HandlerContextWithInferior<'_, 'id, 'disp, 'scope, 'env, 'modules, 'tracer, S>
{
    pub fn process(&self) -> &Process<S> {
        self.child.process()
    }

    pub fn process_mut(&mut self) -> &mut Process<S> {
        self.child.process_mut()
    }
}
