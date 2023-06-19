use procfs::process::Stat;

use super::Process;

impl Process {
    pub fn stats(&self) -> Stat {
        self.procfs().stat().unwrap()
    }
}
