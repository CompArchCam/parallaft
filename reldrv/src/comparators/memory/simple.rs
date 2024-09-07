use std::ops::Range;

use crate::{
    dispatcher::Module,
    error::Result,
    events::comparator::{MemoryComparator, MemoryComparsionResult},
    process::Process,
    utils::compare_memory::compare_memory,
};

// const PAGE_DIFF_BLOCK_SIZE: usize = 64;

pub struct SimpleMemoryComparator {}

impl SimpleMemoryComparator {
    pub fn new() -> Self {
        Self {}
    }
}

impl MemoryComparator for SimpleMemoryComparator {
    fn compare_memory(
        &self,
        page_addresses: &[Range<usize>],
        chk_process: Process<crate::process::state::Stopped>,
        ref_process: Process<crate::process::state::Stopped>,
    ) -> Result<(
        Process<crate::process::state::Stopped>,
        Process<crate::process::state::Stopped>,
        MemoryComparsionResult,
    )> {
        let result = compare_memory(&chk_process, &ref_process, page_addresses)?;

        Ok((chk_process, ref_process, result))
    }
}

impl Module for SimpleMemoryComparator {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_memory_comparator(self);
    }
}
