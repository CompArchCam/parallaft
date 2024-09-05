use crate::error::Result;

use super::process_lifetime::HandlerContext;

#[allow(unused_variables)]
pub trait ModuleLifetimeHook: Sync {
    fn init<'s, 'scope, 'env>(&'s self, ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        Ok(())
    }

    fn fini<'s, 'scope, 'env>(&'s self, ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        Ok(())
    }
}
