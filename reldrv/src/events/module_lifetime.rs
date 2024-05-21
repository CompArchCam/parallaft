use std::thread::Scope;

use crate::error::Result;

#[allow(unused_variables)]
pub trait ModuleLifetimeHook: Sync {
    fn init<'s, 'scope, 'env>(&'s self, scope: &'scope Scope<'scope, 'env>) -> Result<()>
    where
        's: 'scope,
    {
        Ok(())
    }

    fn fini<'s, 'scope, 'env>(&'s self, scope: &'scope Scope<'scope, 'env>) -> Result<()>
    where
        's: 'scope,
    {
        Ok(())
    }
}
