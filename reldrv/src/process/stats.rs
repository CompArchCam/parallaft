use procfs::process::Stat;

use super::{Process, PAGESIZE};
use crate::error::Result;

#[derive(Debug, Clone, Copy)]
pub struct MemoryStats {
    pub dirty_pages: usize,
    pub pss: usize,
    pub pss_pages: usize,
    pub rss: usize,
    pub rss_pages: usize,
}

impl Process {
    pub fn stats(&self) -> Result<Stat> {
        let ret = self.procfs()?.stat()?;
        Ok(ret)
    }

    pub fn memory_stats(&self) -> Result<MemoryStats> {
        let map = &self.procfs()?.smaps_rollup()?.memory_map_rollup.memory_maps[0];

        let pss = *map.extension.map.get("Pss").unwrap() as usize;
        let pss_pages = pss / *PAGESIZE;

        let rss = *map.extension.map.get("Rss").unwrap() as usize;
        let rss_pages = rss / *PAGESIZE;

        Ok(MemoryStats {
            dirty_pages: *map.extension.map.get("Private_Dirty").unwrap() as usize / *PAGESIZE,
            pss,
            pss_pages,
            rss,
            rss_pages,
        })
    }
}
