use procfs::process::Stat;

use super::{state::ProcessState, Process, PAGESIZE};
use crate::error::Result;

#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub private_dirty: u64,
    pub private_dirty_pages: u64,
    pub pss: u64,
    pub pss_pages: u64,
    pub rss: u64,
    pub rss_pages: u64,
}

impl<S: ProcessState> Process<S> {
    pub fn stats(&self) -> Result<Stat> {
        let ret = self.procfs()?.stat()?;
        Ok(ret)
    }

    pub fn memory_stats(&self) -> Result<MemoryStats> {
        let map = &self.procfs()?.smaps_rollup()?.memory_map_rollup.memory_maps[0];

        let pss = *map.extension.map.get("Pss").unwrap();
        let pss_pages = pss / *PAGESIZE as u64;

        let rss = *map.extension.map.get("Rss").unwrap();
        let rss_pages = rss / *PAGESIZE as u64;

        let private_dirty = *map.extension.map.get("Private_Dirty").unwrap();
        let private_dirty_pages = private_dirty / *PAGESIZE as u64;

        Ok(MemoryStats {
            private_dirty,
            private_dirty_pages,
            pss,
            pss_pages,
            rss,
            rss_pages,
        })
    }
}
