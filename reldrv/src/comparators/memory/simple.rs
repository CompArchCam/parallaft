use std::ops::Range;

use crate::{
    dispatcher::Module,
    error::Result,
    events::comparator::{MemoryComparator, MemoryComparsionResult},
    process::Process,
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
        _page_addresses: &[Range<usize>],
        _chk_process: Process<crate::process::state::Stopped>,
        _ref_process: Process<crate::process::state::Stopped>,
    ) -> Result<(
        Process<crate::process::state::Stopped>,
        Process<crate::process::state::Stopped>,
        MemoryComparsionResult,
    )> {
        todo!()
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

// /// Compare the given pages of two processes' memory. Returns if the pages are
// /// equal.
// pub fn page_diff(
//     p1_memory: &impl MemoryAccess,
//     p2_memory: &impl MemoryAccess,
//     page_addresses: &[Range<usize>],
// ) -> Result<bool> {
//     let page_size = { *PAGESIZE };

//     let mut buf_p1 = vec![0_u8; PAGE_DIFF_BLOCK_SIZE * page_size];
//     let mut buf_p2 = vec![0_u8; PAGE_DIFF_BLOCK_SIZE * page_size];

//     let remote_iovs: Vec<IoSlice> = page_addresses
//         .iter()
//         .map(|&p| IoSlice::new(unsafe { slice::from_raw_parts(p as _, page_size) }))
//         .collect();

//     for remote_iov in remote_iovs.chunks(PAGE_DIFF_BLOCK_SIZE) {
//         let local_iov_p1 = IoSliceMut::new(&mut buf_p1[..remote_iov.len() * page_size]);
//         let local_iov_p2 = IoSliceMut::new(&mut buf_p2[..remote_iov.len() * page_size]);

//         p1_memory.read_vectored(remote_iov, &mut [local_iov_p1])?;
//         p2_memory.read_vectored(remote_iov, &mut [local_iov_p2])?;

//         if buf_p1 != buf_p2 {
//             for ((page1, page2), r) in buf_p1
//                 .chunks(page_size)
//                 .zip(buf_p2.chunks(page_size))
//                 .zip(remote_iov)
//             {
//                 if page1 != page2 {
//                     info!("Page mismatch: {:?}", r.as_ptr());

//                     let mismatch_addr = page1
//                         .iter()
//                         .zip(page2.iter())
//                         .position(|(a, b)| a != b)
//                         .unwrap()
//                         & !0x7;

//                     let page1_word = &page1[mismatch_addr..mismatch_addr + 0x8];
//                     let page2_word = &page2[mismatch_addr..mismatch_addr + 0x8];

//                     info!(
//                         "{:02X?} != {:02X?} @ offset {:#0x}",
//                         page1_word, page2_word, mismatch_addr
//                     );

//                     info!(
//                         "Mismatch address: {:#0x}",
//                         r.as_ptr() as usize + mismatch_addr
//                     );

//                     trace!("Page data 1:\n{:?}", page1.hex_dump());
//                     trace!("Page data 2:\n{:?}", page2.hex_dump());
//                 }
//             }

//             return Ok(false);
//         }
//     }

//     Ok(true)
// }
