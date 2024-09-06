use procfs::process::MMPermissions;

use crate::{dispatcher::Module, types::process_id::InferiorId};

use super::{DirtyPageAddressFlags, DirtyPageAddressTracker, DirtyPageAddressesWithFlags};

pub struct AllWritablePageTracker;

impl AllWritablePageTracker {
    pub fn new() -> Self {
        Self
    }
}

impl DirtyPageAddressTracker for AllWritablePageTracker {
    fn take_dirty_pages_addresses(
        &self,
        inferior_id: crate::types::process_id::InferiorId,
        extra_writable_ranges: &[std::ops::Range<usize>],
    ) -> crate::error::Result<super::DirtyPageAddressesWithFlags> {
        let mut addresses = Vec::new();

        match &inferior_id {
            InferiorId::Main(segment) => segment
                .as_ref()
                .unwrap()
                .checkpoint_end()
                .unwrap()
                .process
                .lock()
                .as_ref()
                .unwrap()
                .for_each_writable_map(
                    |m| {
                        if !m.perms.contains(MMPermissions::READ) {
                            return Ok(());
                        }
                        addresses.push(m.address.0 as _..m.address.1 as _);
                        Ok(())
                    },
                    extra_writable_ranges,
                )?,
            InferiorId::Checker(segment) => segment
                .checker_status
                .lock()
                .process()
                .unwrap()
                .for_each_writable_map(
                    |m| {
                        if !m.perms.contains(MMPermissions::READ) {
                            return Ok(());
                        }
                        addresses.push(m.address.0 as _..m.address.1 as _);
                        Ok(())
                    },
                    extra_writable_ranges,
                )?,
        };

        Ok(DirtyPageAddressesWithFlags {
            addresses,
            flags: DirtyPageAddressFlags {
                contains_writable_only: true,
            },
        })
    }
}

impl Module for AllWritablePageTracker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.set_dirty_page_tracker(self);
    }
}
