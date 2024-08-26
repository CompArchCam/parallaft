use crate::{error::Result, process::state::Stopped, types::memory_map::MemoryMap};

use super::HandlerContext;

#[allow(unused_variables)]
pub trait MemoryEventHandler: Sync {
    fn handle_memory_map_created(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        Ok(())
    }

    fn handle_memory_map_removed(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        Ok(())
    }

    fn handle_memory_map_updated(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        Ok(())
    }
}
