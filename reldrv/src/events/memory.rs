use crate::{error::Result, types::memory_map::MemoryMap};

use super::HandlerContext;

#[allow(unused_variables)]
pub trait MemoryEventHandler: Sync {
    fn handle_memory_map_created(&self, map: &MemoryMap, ctx: HandlerContext) -> Result<()> {
        Ok(())
    }

    fn handle_memory_map_removed(&self, map: &MemoryMap, ctx: HandlerContext) -> Result<()> {
        Ok(())
    }

    fn handle_memory_map_updated(&self, map: &MemoryMap, ctx: HandlerContext) -> Result<()> {
        Ok(())
    }
}
