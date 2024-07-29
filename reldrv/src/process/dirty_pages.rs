use std::{
    collections::HashSet,
    io::{IoSlice, IoSliceMut},
    ops::Range,
    slice,
};

use log::{debug, info, trace};

use pretty_hex::PrettyHex;
use procfs::process::{MMPermissions, MMapPath};
use reverie_syscalls::MemoryAccess;

use crate::error::Result;
use crate::process::Process;

use super::PAGESIZE;

const PAGE_DIFF_BLOCK_SIZE: usize = 64;

pub fn merge_page_addresses(
    page_addresses_p1: &[usize],
    page_addresses_p2: &[usize],
    ignored_pages: &[usize],
) -> HashSet<usize> {
    let mut pages: HashSet<usize> = HashSet::new();
    pages.extend(page_addresses_p1);
    pages.extend(page_addresses_p2);

    let pages = pages
        .difference(&ignored_pages.iter().copied().collect::<HashSet<usize>>())
        .cloned()
        .collect::<HashSet<usize>>();

    pages
}

pub fn filter_writable_addresses(
    mut addresses: HashSet<usize>,
    writable_regions: &[Range<usize>],
) -> HashSet<usize> {
    addresses.retain(|a| writable_regions.iter().any(|r| r.contains(a)));
    addresses
}

/// Compare the given pages of two processes' memory. Returns if the pages are
/// equal.
pub fn page_diff(
    p1_memory: &impl MemoryAccess,
    p2_memory: &impl MemoryAccess,
    page_addresses: &HashSet<usize>,
) -> Result<bool> {
    let page_size = { *PAGESIZE };

    let mut buf_p1 = vec![0_u8; PAGE_DIFF_BLOCK_SIZE * page_size];
    let mut buf_p2 = vec![0_u8; PAGE_DIFF_BLOCK_SIZE * page_size];

    let remote_iovs: Vec<IoSlice> = page_addresses
        .iter()
        .map(|&p| IoSlice::new(unsafe { slice::from_raw_parts(p as _, page_size) }))
        .collect();

    for remote_iov in remote_iovs.chunks(PAGE_DIFF_BLOCK_SIZE) {
        let local_iov_p1 = IoSliceMut::new(&mut buf_p1[..remote_iov.len() * page_size]);
        let local_iov_p2 = IoSliceMut::new(&mut buf_p2[..remote_iov.len() * page_size]);

        p1_memory.read_vectored(remote_iov, &mut [local_iov_p1])?;
        p2_memory.read_vectored(remote_iov, &mut [local_iov_p2])?;

        if buf_p1 != buf_p2 {
            for ((page1, page2), r) in buf_p1
                .chunks(page_size)
                .zip(buf_p2.chunks(page_size))
                .zip(remote_iov)
            {
                if page1 != page2 {
                    info!("Page mismatch: {:?}", r.as_ptr());

                    let mismatch_addr = page1
                        .iter()
                        .zip(page2.iter())
                        .position(|(a, b)| a != b)
                        .unwrap()
                        & !0x8;

                    let page1_word = &page1[mismatch_addr..mismatch_addr + 0x8];
                    let page2_word = &page2[mismatch_addr..mismatch_addr + 0x8];

                    info!(
                        "{:02X?} != {:02X?} @ offset {:?}",
                        page1_word, page2_word, mismatch_addr as *const u8
                    );

                    trace!("Page data 1:\n{:?}", page1.hex_dump());
                    trace!("Page data 2:\n{:?}", page2.hex_dump());
                }
            }

            return Ok(false);
        }
    }

    Ok(true)
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFlag {
    SoftDirty,
    UffdWp,
}

impl Process {
    pub fn get_dirty_pages(&self, page_flag: PageFlag) -> Result<Vec<usize>> {
        let maps = self.procfs()?.maps()?;
        let page_size = procfs::page_size();
        let mut pagemap = self.procfs()?.pagemap()?;
        let mut dirty_pages_it: Vec<usize> = Vec::new();

        debug!("Page map for pid {}", self.pid);

        for map in maps {
            debug!(
                "Map: {:?}-{:?}: {:?} @ {:p}",
                map.address.0 as *const u8,
                map.address.1 as *const u8,
                map.pathname,
                map.offset as *const u8
            );
            if [MMapPath::Vdso, MMapPath::Vsyscall, MMapPath::Vvar].contains(&map.pathname) {
                continue;
            }

            let range = (map.address.0 / page_size) as usize..(map.address.1 / page_size) as usize;
            let range_info = pagemap.get_range_info(range)?;

            for (loc, pte) in (map.address.0..map.address.1)
                .step_by(page_size as _)
                .zip(range_info)
            {
                let is_dirty = match pte {
                    procfs::process::PageInfo::MemoryPage(flags) => match page_flag {
                        PageFlag::SoftDirty => {
                            flags.contains(procfs::process::MemoryPageFlags::SOFT_DIRTY)
                        }
                        PageFlag::UffdWp => {
                            !flags.contains(procfs::process::MemoryPageFlags::UFFD_WP)
                        }
                    },
                    procfs::process::PageInfo::SwapPage(flags) => match page_flag {
                        PageFlag::SoftDirty => {
                            flags.contains(procfs::process::SwapPageFlags::SOFT_DIRTY)
                        }
                        PageFlag::UffdWp => {
                            !flags.contains(procfs::process::SwapPageFlags::UFFD_WP)
                        }
                    },
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

    pub fn get_writable_ranges(&self) -> Result<Box<[Range<usize>]>> {
        let mut ranges = Vec::new();

        for map in self.procfs()?.maps()? {
            if map.perms.contains(MMPermissions::WRITE) {
                ranges.push(Range {
                    start: map.address.0 as usize,
                    end: map.address.1 as usize,
                })
            }
        }

        // stitch consecutive ranges
        if ranges.is_empty() {
            return Ok(Vec::new().into_boxed_slice());
        }

        let mut result = Vec::new();
        let mut current_range = ranges[0].clone();

        for next_range in ranges.iter().skip(1) {
            if current_range.end == next_range.start {
                current_range = current_range.start..next_range.end;
            } else {
                result.push(current_range.clone());
                current_range = next_range.clone();
            }
        }

        result.push(current_range);

        Ok(result.into_boxed_slice())
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
