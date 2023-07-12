use procfs::process::Stat;

use super::Process;
use crate::error::Result;

impl Process {
    pub fn stats(&self) -> Result<Stat> {
        let ret = self.procfs()?.stat()?;
        Ok(ret)
    }
}
