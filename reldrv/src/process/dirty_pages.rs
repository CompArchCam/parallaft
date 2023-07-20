use std::{
    collections::HashSet,
    io::{IoSlice, IoSliceMut},
    slice,
};

use log::{debug, info, trace};

use pretty_hex::PrettyHex;
use procfs::process::MMPermissions;
use reverie_syscalls::MemoryAccess;

use crate::error::Result;
use crate::process::Process;

use super::PAGESIZE;

pub fn page_diff(
    p1: &impl MemoryAccess,
    p2: &impl MemoryAccess,
    pages_p1: &[usize],
    pages_p2: &[usize],
) -> Result<bool> {
    let mut pages: HashSet<usize> = HashSet::new();
    pages.extend(pages_p1.iter());
    pages.extend(pages_p2.iter());

    let block_size = 128;
    let page_size = *PAGESIZE as usize;

    let mut buf_p1 = vec![0_u8; block_size * page_size];
    let mut buf_p2 = vec![0_u8; block_size * page_size];

    let remote_iovs: Vec<IoSlice> = pages
        .into_iter()
        .map(|p| IoSlice::new(unsafe { slice::from_raw_parts(p as _, page_size) }))
        .collect();

    for remote_iov in remote_iovs.chunks(block_size) {
        let local_iov_p1 = IoSliceMut::new(&mut buf_p1[..remote_iov.len() * page_size]);
        let local_iov_p2 = IoSliceMut::new(&mut buf_p2[..remote_iov.len() * page_size]);

        p1.read_vectored(remote_iov, &mut [local_iov_p1])?;
        p2.read_vectored(remote_iov, &mut [local_iov_p2])?;

        trace!(
            "page data p1@{:p}:\n{:?}",
            remote_iov[0].as_ptr(),
            &buf_p1[..remote_iov.len() * page_size].hex_dump()
        );
        trace!(
            "page data p2@{:p}:\n{:?}",
            remote_iov[0].as_ptr(),
            &buf_p2[..remote_iov.len() * page_size].hex_dump()
        );

        if buf_p1 != buf_p2 {
            info!(
                "Page data does not match: {:?}",
                remote_iov
                    .iter()
                    .map(|i| i.as_ptr())
                    .collect::<Vec<*const u8>>()
            );
            return Ok(false);
        }
    }

    Ok(true)
}

#[allow(unused)]
impl Process {
    pub fn dirty_page_delta_against(
        &self,
        other: &Process,
        ignored_pages: &[usize],
    ) -> Result<(bool, usize)> {
        let dirty_pages_myself: Vec<usize> = self
            .get_dirty_pages()?
            .into_iter()
            .filter(|addr| !ignored_pages.contains(addr))
            .collect();

        let dirty_pages_other: Vec<usize> = other
            .get_dirty_pages()?
            .into_iter()
            .filter(|addr| !ignored_pages.contains(addr))
            .collect();

        info!("{} dirty pages", dirty_pages_myself.len());

        Ok((
            page_diff(self, other, &dirty_pages_myself, &dirty_pages_other)?,
            dirty_pages_myself.len(),
        ))
    }

    pub fn get_dirty_pages(&self) -> Result<Vec<usize>> {
        let maps = self.procfs()?.maps()?;
        let page_size = procfs::page_size();
        let mut pagemap = self.procfs()?.pagemap()?;
        let mut dirty_pages_it: Vec<usize> = Vec::new();

        debug!("Page map for pid {}", self.pid);

        for map in maps
            .iter()
            .filter(|m| m.perms.contains(procfs::process::MMPermissions::WRITE))
        {
            debug!(
                "Writable map: {:?}-{:?}: {:?} @ {:p}",
                map.address.0 as *const u8,
                map.address.1 as *const u8,
                map.pathname,
                map.offset as *const u8
            );
            let range = (map.address.0 / page_size) as usize..(map.address.1 / page_size) as usize;
            let range_info = pagemap.get_range_info(range)?;

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
                    dirty_pages_it.push(loc as _);
                }
            }
        }

        Ok(dirty_pages_it)
    }

    pub fn clear_dirty_page_bits(&self) -> Result<()> {
        self.procfs()?.clear_refs(4)?;

        Ok(())
    }

    pub fn dump_memory_maps(&self) -> Result<()> {
        fn perm_to_str<'a>(
            perms: MMPermissions,
            bit: MMPermissions,
            yes: &'a str,
            no: &'a str,
        ) -> &'a str {
            if perms.contains(bit) {
                yes
            } else {
                no
            }
        }

        for map in self.procfs()?.maps()? {
            let mut perms_string = String::new();

            perms_string += perm_to_str(map.perms, MMPermissions::READ, "r", "-");
            perms_string += perm_to_str(map.perms, MMPermissions::WRITE, "w", "-");
            perms_string += perm_to_str(map.perms, MMPermissions::EXECUTE, "x", "-");
            perms_string += perm_to_str(map.perms, MMPermissions::PRIVATE, "p", "");
            perms_string += perm_to_str(map.perms, MMPermissions::SHARED, "s", "");

            info!(
                "{:?}-{:?} {}: {:?} @ {:p}",
                map.address.0 as *const u8,
                map.address.1 as *const u8,
                perms_string,
                map.pathname,
                map.offset as *const u8
            );
        }

        Ok(())
    }
}

pub trait IgnoredPagesProvider {
    fn get_ignored_pages(&self) -> Box<[usize]>;
}
