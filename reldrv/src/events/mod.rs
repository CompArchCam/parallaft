pub mod process_lifetime;
pub mod signal;
pub mod syscall;

use std::thread::Scope;

use crate::{
    check_coord::{CheckCoordinator, ProcessIdentityRef, UpgradableReadGuard},
    process::Process,
    types::segment::Segment,
};

pub struct HandlerContext<'id, 'process, 'disp, 'scope, 'env, 'modules> {
    pub child: &'id mut ProcessIdentityRef<'process, UpgradableReadGuard<Segment>>,
    pub check_coord: &'disp CheckCoordinator<'disp, 'modules>,
    pub scope: &'scope Scope<'scope, 'env>,
}

impl HandlerContext<'_, '_, '_, '_, '_, '_> {
    pub fn process(&self) -> &Process {
        self.child.process().unwrap()
    }
}
