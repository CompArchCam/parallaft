
use log::{debug, trace};

#[derive(Debug)]
pub struct DirtyPageTracer {
    pub pid: i32,
    proc: procfs::process::Process,
}

impl DirtyPageTracer {
    pub fn new(pid: i32) -> Self {
        let proc = procfs::process::Process::new(pid).expect("failed to open procfs");
        Self { pid, proc }
    }

    pub fn clear_dirty_bits(&self) {
        self.proc.clear_refs(4).expect("failed to clear dirty bits");
    }

    pub fn get_dirty_pages(&self) -> Vec<u64> {
        let maps = self.proc.maps().expect("failed to read memory map");
        let page_size = procfs::page_size();
        let mut pagemap = self.proc.pagemap().expect("failed to open pagemap");
        let mut dirty_pages_it: Vec<u64> = Vec::new();

        debug!("Page map for pid {}", self.pid);

        for map in maps
            .iter()
            .filter(|m| m.perms.contains(procfs::process::MMPermissions::WRITE))
        {
            debug!(
                "Writable map: {:?}-{:?}: {:?}",
                map.address.0 as *const u8, map.address.1 as *const u8, map.pathname
            );
            let range = (map.address.0 / page_size) as usize..(map.address.1 / page_size) as usize;
            let range_info = pagemap
                .get_range_info(range)
                .expect("failed to get range info from pagemap");

            for (loc, pte) in (map.address.0..map.address.1)
                .step_by(page_size as _)
                .zip(range_info)
            {
                let is_dirty = match pte {
                    procfs::process::PageInfo::MemoryPage(flags) => {
                        flags.contains(procfs::process::MemoryPageFlags::SOFT_DIRTY)
                    }
                    procfs::process::PageInfo::SwapPage(flags) => {
                        flags.contains(procfs::process::SwapPageFlags::SOFT_DIRTY)
                    }
                };

                if is_dirty {
                    trace!("Dirty page: {:?}", loc as *const u8);
                    dirty_pages_it.push(loc);
                }
            }
        }

        dirty_pages_it
    }
}
