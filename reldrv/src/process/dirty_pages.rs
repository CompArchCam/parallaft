use std::{fmt::Display, ops::Range, os::fd::AsRawFd, slice};

use bitflags::bitflags;
use log::{debug, info, trace};

use nix::{errno::Errno, ioctl_readwrite};
use procfs::{
    process::{MMPermissions, MMapPath, MemoryMap, MemoryPageFlags, PageInfo, SwapPageFlags},
    KPageCount,
};
use try_insert_ext::OptionInsertExt;

use crate::error::{Error, Result};
use crate::process::Process;

use super::state::ProcessState;

pub fn merge_page_addresses(
    page_addresses_p1: &[Range<usize>],
    page_addresses_p2: &[Range<usize>],
    ignored_pages: &[Range<usize>],
) -> Vec<Range<usize>> {
    // Step 1: Merge the two lists of ranges
    let mut merged_ranges: Vec<Range<usize>> = page_addresses_p1
        .iter()
        .chain(page_addresses_p2.iter())
        .cloned()
        .collect();

    // Step 2: Sort ranges by start (and end as a secondary criterion)
    merged_ranges.sort_by_key(|r| (r.start, r.end));

    // Step 3: Merge overlapping or consecutive ranges
    let mut consolidated_ranges: Vec<Range<usize>> = Vec::new();
    for range in merged_ranges {
        if let Some(last_range) = consolidated_ranges.last_mut() {
            if last_range.end >= range.start {
                // If the current range overlaps or is adjacent to the last range, merge them
                last_range.end = last_range.end.max(range.end);
            } else {
                // Otherwise, just add the current range to the list
                consolidated_ranges.push(range);
            }
        } else {
            consolidated_ranges.push(range);
        }
    }

    // Step 4: Exclude ignored pages
    let mut result: Vec<Range<usize>> = Vec::new();
    for range in consolidated_ranges {
        let mut current_start = range.start;

        for ignored in ignored_pages {
            if ignored.end <= current_start {
                // The ignored range is completely before the current range
                continue;
            }
            if ignored.start >= range.end {
                // The ignored range is completely after the current range
                break;
            }

            if ignored.start > current_start {
                // Add the part before the ignored range
                result.push(current_start..ignored.start);
            }

            // Move the start to the end of the ignored range
            current_start = current_start.max(ignored.end);
        }

        if current_start < range.end {
            // Add the remaining part of the range that wasn't ignored
            result.push(current_start..range.end);
        }
    }

    result
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug, Clone, Copy)]
struct page_region {
    start: u64,
    end: u64,
    categories: u64,
}

#[repr(C)]
#[allow(non_camel_case_types)]
#[derive(Debug)]
struct pm_scan_arg {
    size: u64,
    flags: u64,
    start: u64,
    end: u64,
    walk_end: u64,
    vec: u64,
    vec_len: u64,
    max_pages: u64,
    category_inverted: u64,
    category_mask: u64,
    category_anyof_mask: u64,
    return_mask: u64,
}

ioctl_readwrite!(ioctl_pagemap_scan, b'f', 16, pm_scan_arg);

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq)]
    pub struct PageCategory: u64 {
        const WPALLOWED = 1 << 0;
        const WRITTEN = 1 << 1;
        const FILE = 1 << 2;
        const PRESENT = 1 << 3;
        const SWAPPED = 1 << 4;
        const PFNZERO = 1 << 5;
        const HUGE = 1 << 6;
        const SOFT_DIRTY = 1 << 7;
        const UNIQUE = 1 << 8;
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum PageFlagType {
    SoftDirty,
    UffdWp,
    KPageCountEqualsOne,
}

impl Display for PageFlagType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PageFlagType::SoftDirty => write!(f, "soft dirty"),
            PageFlagType::UffdWp => write!(f, "uffd wp"),
            PageFlagType::KPageCountEqualsOne => write!(f, "kpagecount1"),
        }
    }
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

    pub fn pagemap_scan(
        &self,
        start_addr: usize,
        end_addr: usize,
        category_inverted: PageCategory,
        category_mask: PageCategory,
        category_anyof_mask: PageCategory,
        return_mask: PageCategory,
    ) -> Result<Vec<(Range<usize>, PageCategory)>> {
        let pagemap = self.procfs()?.open_relative("pagemap")?;

        const BLOCK_SIZE: usize = 8192;

        let mut buffer: Vec<page_region> = Vec::with_capacity(BLOCK_SIZE);
        let mut result = Vec::new();

        let mut walk_end = start_addr;

        while walk_end < end_addr {
            let mut args = pm_scan_arg {
                size: std::mem::size_of::<pm_scan_arg>() as _,
                flags: 0,
                start: walk_end as _,
                end: end_addr as _,
                walk_end: 0,
                vec: buffer.as_mut_ptr() as _,
                vec_len: buffer.capacity() as _,
                max_pages: 0,
                category_inverted: category_inverted.bits(),
                category_mask: category_mask.bits(),
                category_anyof_mask: category_anyof_mask.bits(),
                return_mask: return_mask.bits(),
            };

            let sz =
                unsafe { ioctl_pagemap_scan(pagemap.as_raw_fd(), &mut args as *mut _) }? as usize;

            assert!(sz <= args.vec_len as _);

            unsafe { buffer.set_len(sz) };

            result.extend(buffer.iter().map(|region| {
                (
                    (region.start as usize..region.end as usize),
                    PageCategory::from_bits_retain(region.categories),
                )
            }));

            walk_end = args.walk_end as usize;
        }

        Ok(result)
    }

    pub fn get_dirty_pages(
        &self,
        page_flag: PageFlagType,
        extra_writable_ranges: &[Range<usize>],
        use_pagemap_scan_ioctl: bool,
    ) -> Result<Vec<Range<usize>>> {
        if use_pagemap_scan_ioctl {
            self.get_dirty_pages_pagemap_scan_ioctl(page_flag, extra_writable_ranges)
        } else {
            self.get_dirty_pages_userspace_scan(page_flag, extra_writable_ranges)
        }
    }

    pub fn get_dirty_pages_pagemap_scan_ioctl(
        &self,
        page_flag: PageFlagType,
        extra_writable_ranges: &[Range<usize>],
    ) -> Result<Vec<Range<usize>>> {
        let mut result = Vec::new();

        self.for_each_writable_map(
            |map| {
                debug!(
                    "Map: {:?}-{:?}: {:?} @ {:p}",
                    map.address.0 as *const u8,
                    map.address.1 as *const u8,
                    map.pathname,
                    map.offset as *const u8
                );

                let flag = match page_flag {
                    PageFlagType::SoftDirty => PageCategory::SOFT_DIRTY,
                    PageFlagType::UffdWp => PageCategory::WRITTEN,
                    PageFlagType::KPageCountEqualsOne => PageCategory::UNIQUE,
                };

                let pages = self.pagemap_scan(
                    map.address.0 as usize,
                    map.address.1 as usize,
                    PageCategory::empty(),
                    flag,
                    PageCategory::empty(),
                    flag,
                )?;

                result.extend(pages.into_iter().map(|(range, _)| range));

                Ok(())
            },
            extra_writable_ranges,
        )?;

        Ok(result)
    }

    pub fn get_dirty_pages_userspace_scan(
        &self,
        page_flag: PageFlagType,
        extra_writable_ranges: &[Range<usize>],
    ) -> Result<Vec<Range<usize>>> {
        let page_size = procfs::page_size();
        let mut pagemap = self.procfs()?.pagemap()?;
        let mut dirty_pages_it: Vec<Range<usize>> = Vec::new();

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
                        PageFlagType::SoftDirty => match pte {
                            PageInfo::MemoryPage(flags) => {
                                flags.contains(MemoryPageFlags::SOFT_DIRTY)
                            }
                            PageInfo::SwapPage(flags) => flags.contains(SwapPageFlags::SOFT_DIRTY),
                        },
                        PageFlagType::UffdWp => !match pte {
                            PageInfo::MemoryPage(flags) => flags.contains(MemoryPageFlags::UFFD_WP),
                            PageInfo::SwapPage(flags) => flags.contains(SwapPageFlags::UFFD_WP),
                        },
                        PageFlagType::KPageCountEqualsOne => {
                            match pte {
                                PageInfo::MemoryPage(flags) => {
                                    if !flags.contains(MemoryPageFlags::PRESENT) {
                                        continue;
                                    }
                                    let pfn = flags.get_page_frame_number();
                                    if pfn.0 == 0 {
                                        return Err(Error::Nix(Errno::EPERM));
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
                        if let Some(last) = dirty_pages_it.last_mut() {
                            if last.end == loc as _ {
                                last.end += page_size as usize;
                            } else {
                                dirty_pages_it.push(loc as _..(loc + page_size) as _);
                            }
                        } else {
                            dirty_pages_it.push(loc as _..(loc + page_size) as _);
                        }

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

    pub fn get_writable_ranges(&self) -> Result<Vec<Range<usize>>> {
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
            return Ok(Vec::new());
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

        Ok(result)
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
    use nix::sys::{
        mman::{mmap, MapFlags, ProtFlags},
        signal::{raise, Signal},
        wait::WaitStatus,
    };

    use crate::{
        process::{dirty_pages::PageCategory, state::WithProcess, PAGESIZE},
        test_utils::ptraced,
    };

    use super::merge_page_addresses;
    use std::{num::NonZero, ops::Range, os::fd::OwnedFd, usize};

    #[test]
    fn test_merge_page_addresses_overlap_with_ignored() {
        let p1 = vec![0..10, 20..30];
        let p2 = vec![5..15, 25..35];
        let ignored = vec![12..13, 28..32];

        let result = merge_page_addresses(&p1, &p2, &ignored);
        assert_eq!(result, vec![0..12, 13..15, 20..28, 32..35]);
    }

    #[test]
    fn test_merge_page_addresses_complete_overlap_with_ignored() {
        let p1 = vec![0..10];
        let p2 = vec![5..15];
        let ignored = vec![0..20]; // Ignore the entire range

        let result = merge_page_addresses(&p1, &p2, &ignored);
        assert_eq!(result, Vec::<Range<usize>>::new());
    }

    #[test]
    fn test_merge_page_addresses_non_consecutive_ranges_with_ignored() {
        let p1 = vec![0..5, 10..15, 20..25];
        let p2 = vec![5..10, 15..20];
        let ignored = vec![7..8, 17..18];

        let result = merge_page_addresses(&p1, &p2, &ignored);
        assert_eq!(result, vec![0..7, 8..17, 18..25]);
    }

    #[test]
    #[ignore = "requires custom kernel"]
    fn test_pagemap_scan_unique() -> crate::error::Result<()> {
        let page_size = *PAGESIZE as usize;

        let buf = unsafe {
            mmap::<OwnedFd>(
                None,
                NonZero::new_unchecked(page_size * 2),
                ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
                MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
                None,
                0,
            )
        }? as *mut u8;

        let mut process = ptraced(|| {
            unsafe { *buf = 2 };
            raise(Signal::SIGTSTP).unwrap();
            0
        });

        let status;
        WithProcess(process, status) = process.cont()?.waitpid()?.unwrap_stopped();
        assert_eq!(status, WaitStatus::Stopped(process.pid, Signal::SIGTSTP));

        unsafe { *buf = 1 };

        let result = process
            .pagemap_scan(
                buf as usize,
                buf as usize + page_size * 2,
                PageCategory::empty(),
                PageCategory::UNIQUE,
                PageCategory::empty(),
                PageCategory::UNIQUE,
            )
            .unwrap();

        dbg!(&result);

        // The first page should be unique because it is COW-ed
        assert!(result
            .iter()
            .any(|x| (buf as usize) >= x.0.start && (buf as usize) < x.0.end));

        // The second page should not be, as it is not modified
        assert!(!result.iter().any(
            |x| (buf as usize + page_size) >= x.0.start && (buf as usize + page_size) < x.0.end
        ));

        Ok(())
    }
}
