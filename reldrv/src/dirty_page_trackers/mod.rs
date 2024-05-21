pub mod fpt;
pub mod soft_dirty;

use std::{fmt::Debug, ops::Range};

use crate::{error::Result, types::process_id::InferiorId};

#[derive(Debug, Clone, Copy, Default)]
pub struct DirtyPageAddressFlags {
    pub contains_writable_only: bool,
}

pub struct DirtyPageAddressesWithFlags {
    pub addresses: Box<dyn AsRef<[usize]> + Send + Sync>,
    pub flags: DirtyPageAddressFlags,
}

impl DirtyPageAddressesWithFlags {
    pub fn empty() -> Self {
        Self {
            addresses: Box::new(vec![]),
            flags: Default::default(),
        }
    }
}

impl Debug for DirtyPageAddressesWithFlags {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("DirtyPageAddressFlags")
            .field("contains_writable_only", &self.flags.contains_writable_only)
            .field("addresses", &self.addresses.as_ref().as_ref())
            .finish()
    }
}

#[allow(unused_variables)]
pub trait DirtyPageAddressTracker {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: InferiorId,
    ) -> Result<DirtyPageAddressesWithFlags>;

    fn nr_dirty_pages(&self, inferior_id: InferiorId) -> Result<usize>;
}

#[allow(unused_variables)]
pub trait ExtraWritableRangesProvider {
    fn get_extra_writable_ranges(&self) -> Box<[Range<usize>]>;
}
