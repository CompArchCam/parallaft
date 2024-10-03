pub mod full;
pub mod kpagecount;
pub mod null;
pub mod soft_dirty;
#[cfg(feature = "dpt_uffd")]
pub mod uffd;

use cfg_if::cfg_if;
use clap::ValueEnum;
use log::warn;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Range};

use crate::{
    error::Result,
    features::{pagemap_scan::PAGEMAP_SCAN_UNIQUE_FEATURE, Feature},
    process::PAGESIZE,
    types::process_id::InferiorId,
};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum DirtyPageAddressTrackerType {
    SoftDirty,
    #[cfg(feature = "dpt_uffd")]
    Uffd,
    KPageCount,
    PagemapScanUnique,
    PagemapScanSoftDirty,
    Full,
    None,
}

impl Default for DirtyPageAddressTrackerType {
    fn default() -> Self {
        cfg_if! {
            if #[cfg(target_arch = "aarch64")] {
                use crate::features::dirty_page_userspace_scan::KPAGECOUNT_FEATURE;

                if PAGEMAP_SCAN_UNIQUE_FEATURE.is_available().is_ok() {
                    Self::PagemapScanUnique
                }
                else if KPAGECOUNT_FEATURE.is_available().is_ok() {
                    Self::KPageCount
                }
                else {
                    warn!("No dirty page address tracker available, checking all writable pages");
                    Self::Full
                }
            }
            else {
                use crate::features::{dirty_page_userspace_scan::SOFT_DIRTY_FEATURE, pagemap_scan::PAGEMAP_SCAN_SOFT_DIRTY_FEATURE};

                if PAGEMAP_SCAN_UNIQUE_FEATURE.is_available().is_ok() {
                    Self::PagemapScanUnique
                }
                else if PAGEMAP_SCAN_SOFT_DIRTY_FEATURE.is_available().is_ok() {
                    Self::PagemapScanSoftDirty
                }
                else if SOFT_DIRTY_FEATURE.is_available().is_ok() {
                    Self::SoftDirty
                }
                else {
                    warn!("No dirty page address tracker available, checking all writable pages");
                    Self::Full
                }
            }
        }
    }
}

#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyPageAddressFlags {
    pub contains_writable_only: bool,
}

#[derive(Debug, Clone)]
pub struct DirtyPageAddressesWithFlags {
    pub addresses: Vec<Range<usize>>,
    pub flags: DirtyPageAddressFlags,
}

impl DirtyPageAddressesWithFlags {
    pub fn nr_dirty_pages(&self) -> usize {
        self.addresses
            .iter()
            .map(|range| (range.end - range.start) / *PAGESIZE)
            .sum()
    }

    pub fn nr_segments(&self) -> usize {
        self.addresses.len()
    }
}

impl DirtyPageAddressesWithFlags {
    pub fn empty() -> Self {
        Self {
            addresses: Vec::new(),
            flags: Default::default(),
        }
    }
}

#[allow(unused_variables)]
pub trait DirtyPageAddressTracker: Sync {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: InferiorId,
        extra_writable_ranges: &[Range<usize>],
    ) -> Result<DirtyPageAddressesWithFlags>;

    fn nr_dirty_pages(&self, inferior_id: InferiorId) -> Result<usize> {
        Ok(match inferior_id {
            InferiorId::Main(segment) => {
                segment
                    .unwrap()
                    .status
                    .lock()
                    .process()
                    .unwrap()
                    .memory_stats()?
                    .private_dirty_pages as _
            }
            InferiorId::Checker(_, exec) => {
                exec.status
                    .lock()
                    .process()
                    .unwrap()
                    .memory_stats()?
                    .private_dirty_pages as _
            }
        })
    }
}

#[allow(unused_variables)]
pub trait ExtraWritableRangesProvider: Sync {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]>;
}
