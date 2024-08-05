pub mod comparator;
pub mod insn_patching;
pub mod memory;
pub mod module_lifetime;
pub mod process_lifetime;
pub mod segment;
pub mod signal;
pub mod syscall;

use std::thread::Scope;

use crate::{
    check_coord::CheckCoordinator, process::OwnedProcess, types::process_id::InferiorRefMut,
};

pub struct HandlerContext<'ido, 'id, 'disp, 'scope, 'env, 'modules, 'tracer> {
    pub child: &'ido mut InferiorRefMut<'id>,
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    pub scope: &'scope Scope<'scope, 'env>,
}

pub fn hctx<'ido, 'id, 'disp, 'scope, 'env, 'modules, 'tracer>(
    child: &'ido mut InferiorRefMut<'id>,
    check_coord: &'disp CheckCoordinator<'disp, 'modules, 'tracer>,
    scope: &'scope Scope<'scope, 'env>,
) -> HandlerContext<'ido, 'id, 'disp, 'scope, 'env, 'modules, 'tracer> {
    HandlerContext {
        child,
        check_coord,
        scope,
    }
}

impl<'id, 'disp, 'scope, 'env, 'modules, 'tracer>
    HandlerContext<'_, 'id, 'disp, 'scope, 'env, 'modules, 'tracer>
{
    pub fn process(&self) -> &OwnedProcess {
        self.child.process()
    }

    pub fn process_mut(&mut self) -> &mut OwnedProcess {
        self.child.process_mut()
    }
}
