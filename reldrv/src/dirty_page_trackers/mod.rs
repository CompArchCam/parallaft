#[cfg(feature = "dpt_fpt")]
pub mod fpt;
pub mod kpagecount;
pub mod null;
pub mod soft_dirty;
#[cfg(feature = "dpt_uffd")]
pub mod uffd;

use cfg_if::cfg_if;
use clap::ValueEnum;
use serde::{Deserialize, Serialize};
use std::{fmt::Debug, ops::Range};

use crate::{error::Result, types::process_id::InferiorId};

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Serialize, Deserialize)]
pub enum DirtyPageAddressTrackerType {
    SoftDirty,
    #[cfg(feature = "dpt_fpt")]
    Fpt,
    #[cfg(feature = "dpt_uffd")]
    Uffd,
    KPageCount,
    None,
}

impl Default for DirtyPageAddressTrackerType {
    fn default() -> Self {
        cfg_if! {
            if #[cfg(target_arch = "aarch64")] {
                Self::KPageCount
            }
            else {
                Self::SoftDirty
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
    pub fn empty() -> Self {
        Self {
            addresses: Vec::new(),
            flags: Default::default(),
        }
    }
}

#[allow(unused_variables)]
pub trait DirtyPageAddressTracker {
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
                    .dirty_pages
            }
            InferiorId::Checker(segment) => {
                segment
                    .checker_status
                    .lock()
                    .process()
                    .unwrap()
                    .memory_stats()?
                    .dirty_pages
            }
        })
    }
}

#[allow(unused_variables)]
pub trait ExtraWritableRangesProvider {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]>;
}
