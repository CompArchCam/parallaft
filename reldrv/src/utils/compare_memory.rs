use std::{
    io::{IoSlice, IoSliceMut},
    ops::Range,
};

use reverie_syscalls::MemoryAccess;

use crate::{
    error::Result,
    events::comparator::{MemoryComparsionResult, MemoryMismatch},
};

const BLOCK_SIZE: usize = 1024 * 1024 * 8; /* 8MB */

/// Compare the given pages of two processes' memory. Returns if the pages are
/// equal.
pub fn compare_memory(
    p1_memory: &impl MemoryAccess,
    p2_memory: &impl MemoryAccess,
    address_ranges: &[Range<usize>],
) -> Result<MemoryComparsionResult> {
    let mut buf_p1 = vec![0u8; BLOCK_SIZE];
    let mut buf_p2 = vec![0u8; BLOCK_SIZE];

    // split address_ranges into blocks
    let mut remote_iovs = Vec::new();
    for address_range in address_ranges {
        let mut start = address_range.start;
        while start < address_range.end {
            let end = (start + BLOCK_SIZE).min(address_range.end);
            remote_iovs.push(IoSlice::new(unsafe {
                std::slice::from_raw_parts(start as *const u8, end - start)
            }));
            start = end;
        }
    }

    for remote_iov in remote_iovs {
        let local_iov_p1 = IoSliceMut::new(&mut buf_p1[..remote_iov.len()]);
        let local_iov_p2 = IoSliceMut::new(&mut buf_p2[..remote_iov.len()]);

        p1_memory.read_vectored(&[remote_iov], &mut [local_iov_p1])?;
        p2_memory.read_vectored(&[remote_iov], &mut [local_iov_p2])?;

        if buf_p1 != buf_p2 {
            // find the first index where the two buffers differ
            let i = buf_p1
                .iter()
                .zip(buf_p2.iter())
                .position(|(a, b)| a != b)
                .unwrap()
                & !0x7; // align down to 8 bytes

            let data1 = u64::from_le_bytes(buf_p1[i..i + 8].try_into().unwrap());
            let data2 = u64::from_le_bytes(buf_p2[i..i + 8].try_into().unwrap());

            return Ok(MemoryComparsionResult::Fail {
                first_mismatch: Some(MemoryMismatch {
                    addr: i + remote_iov.as_ptr() as usize,
                    data1,
                    data2,
                }),
            });
        }
    }

    Ok(MemoryComparsionResult::Pass)
}
