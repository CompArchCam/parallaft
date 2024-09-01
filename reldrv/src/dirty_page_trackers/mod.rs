#[cfg(feature = "dpt_fpt")]
pub mod fpt;
pub mod kpagecount;
pub mod null;
pub mod soft_dirty;
#[cfg(feature = "dpt_uffd")]
pub mod uffd;

use std::{fmt::Debug, ops::Range};

use crate::{error::Result, types::process_id::InferiorId};

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
