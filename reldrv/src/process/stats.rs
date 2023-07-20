use procfs::process::Stat;

use super::{Process, PAGESIZE};
use crate::error::Result;

impl Process {
    pub fn stats(&self) -> Result<Stat> {
        let ret = self.procfs()?.stat()?;
        Ok(ret)
    }

    pub fn nr_dirty_pages(&self) -> Result<usize> {
        Ok(
            (*self.procfs()?.smaps_rollup()?.memory_map_rollup.memory_maps[0]
                .extension
                .map
                .get("Private_Dirty")
                .unwrap()
                / *PAGESIZE) as usize,
        )
    }
}
