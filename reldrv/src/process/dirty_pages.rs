use std::{
    collections::{BTreeSet, HashSet},
    ops::Range,
    slice,
};

use log::{debug, info, trace};

use procfs::{
    process::{MMPermissions, MMapPath, MemoryMap, MemoryPageFlags, PageInfo, SwapPageFlags},
    KPageCount,
};
use try_insert_ext::OptionInsertExt;

use crate::error::Result;
use crate::process::Process;

use super::{state::ProcessState, PAGESIZE};

pub fn merge_page_addresses(
    page_addresses_p1: &[usize],
    page_addresses_p2: &[usize],
    ignored_pages: &[usize],
) -> Vec<Range<usize>> {
    let mut pages: HashSet<usize> = HashSet::new();
    pages.extend(page_addresses_p1);
    pages.extend(page_addresses_p2);

    let pages = pages
        .difference(&ignored_pages.iter().copied().collect::<HashSet<usize>>())
        .cloned()
        .collect::<BTreeSet<usize>>();

    pages.into_iter().fold(Vec::new(), |mut acc, page| {
        if acc.is_empty() {
            acc.push(page..page + *PAGESIZE);
        } else {
            let last_range = acc.last_mut().unwrap();
            if last_range.end == page {
                last_range.end += *PAGESIZE;
            } else {
                acc.push(page..page + *PAGESIZE);
            }
        }
        acc
    })
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PageFlag {
    SoftDirty,
    UffdWp,
    KPageCountEqualsOne,
}

impl<S: ProcessState> Process<S> {
    pub fn for_each_writable_map<F>(
        &self,
        mut f: F,
        extra_writable_ranges: &[Range<usize>],
    ) -> Result<()>
    where
        F: FnMut(procfs::process::MemoryMap) -> Result<()>,
    {
        for map in self.procfs()?.maps()? {
            if (map.perms.contains(MMPermissions::WRITE)
                && ![MMapPath::Vdso, MMapPath::Vsyscall, MMapPath::Vvar].contains(&map.pathname))
                || extra_writable_ranges
                    .iter()
                    .any(|r| (map.address.0 < r.end as u64 && map.address.1 > r.start as u64))
            {
                f(map)?;
            }
        }

        Ok(())
    }

    pub fn get_dirty_pages(
        &self,
        page_flag: PageFlag,
        extra_writable_ranges: &[Range<usize>],
    ) -> Result<Vec<usize>> {
        let page_size = procfs::page_size();
        let mut pagemap = self.procfs()?.pagemap()?;
        let mut dirty_pages_it: Vec<usize> = Vec::new();

        let mut kpagecount = None;

        debug!("Page map for pid {}", self.pid);

        self.for_each_writable_map(
            |map| {
                debug!(
                    "Map: {:?}-{:?}: {:?} @ {:p}",
                    map.address.0 as *const u8,
                    map.address.1 as *const u8,
                    map.pathname,
                    map.offset as *const u8
                );

                let range =
                    (map.address.0 / page_size) as usize..(map.address.1 / page_size) as usize;
                let range_info = pagemap.get_range_info(range)?;
                let mut dirty_page_count: usize = 0;

                for (loc, pte) in (map.address.0..map.address.1)
                    .step_by(page_size as _)
                    .zip(range_info)
                {
                    let is_dirty = match page_flag {
                        PageFlag::SoftDirty => match pte {
                            PageInfo::MemoryPage(flags) => {
                                flags.contains(MemoryPageFlags::SOFT_DIRTY)
                            }
                            PageInfo::SwapPage(flags) => flags.contains(SwapPageFlags::SOFT_DIRTY),
                        },
                        PageFlag::UffdWp => !match pte {
                            PageInfo::MemoryPage(flags) => flags.contains(MemoryPageFlags::UFFD_WP),
                            PageInfo::SwapPage(flags) => flags.contains(SwapPageFlags::UFFD_WP),
                        },
                        PageFlag::KPageCountEqualsOne => {
                            match pte {
                                PageInfo::MemoryPage(flags) => {
                                    if !flags.contains(MemoryPageFlags::PRESENT) {
                                        continue;
                                    }
                                    let pfn = flags.get_page_frame_number();
                                    if pfn.0 == 0 {
                                        panic!("Unexpected PFN, check your permissions");
                                    }
                                    kpagecount
                                        .get_or_try_insert_with(|| KPageCount::new())?
                                        .get_count_at_pfn(pfn)?
                                        == 1
                                }
                                PageInfo::SwapPage(_) => {
                                    // we don't know whether the page is dirty or not
                                    true
                                }
                            }
                        }
                    };

                    if is_dirty {
                        trace!("Dirty page: {:?}", loc as *const u8);
                        dirty_pages_it.push(loc as _);
                        dirty_page_count += 1;
                    }
                }
                debug!("{} dirty pages", dirty_page_count);
                Ok(())
            },
            extra_writable_ranges,
        )?;

        Ok(dirty_pages_it)
    }

    pub fn clear_dirty_page_bits(&mut self) -> Result<()> {
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

pub trait AsIoSlice {
    fn as_io_slice(&self) -> std::io::IoSlice<'static>;
}

impl AsIoSlice for MemoryMap {
    fn as_io_slice(&self) -> std::io::IoSlice<'static> {
        unsafe {
            std::io::IoSlice::new(slice::from_raw_parts(
                self.address.0 as *const u8,
                (self.address.1 - self.address.0) as usize,
            ))
        }
    }
}

pub trait IgnoredPagesProvider {
    fn get_ignored_pages(&self) -> Box<[usize]>;
}

#[cfg(test)]
mod tests {
    use itertools::Itertools;

    use crate::process::PAGESIZE;

    use super::merge_page_addresses;

    #[test]
    fn test_merge_page_addresses() {
        let page_addresses_p1 = vec![1, 2, 3, 5, 7]
            .into_iter()
            .map(|x| x * *PAGESIZE)
            .collect_vec();
        let page_addresses_p2 = vec![5, 6, 7]
            .into_iter()
            .map(|x| x * *PAGESIZE)
            .collect_vec();

        let addresses = merge_page_addresses(&page_addresses_p1, &page_addresses_p2, &[]);

        let expected = vec![1..4, 5..8]
            .into_iter()
            .map(|x| (x.start * *PAGESIZE)..(x.end * *PAGESIZE))
            .collect_vec();

        assert_eq!(addresses, expected);
    }
}
