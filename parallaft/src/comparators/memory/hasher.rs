use std::{io::IoSlice, ops::Range};

use log::debug;
use nix::sys::mman::{MapFlags, ProtFlags};
use reverie_syscalls::MemoryAccess;

use crate::{
    dispatcher::Module,
    error::Result,
    events::comparator::{MemoryComparator, MemoryComparsionResult},
    process::{
        state::{Stopped, WithProcess},
        Process, PAGESIZE,
    },
    utils::injector::inject_and_run,
};

#[repr(C)]
struct HasherArgs {
    addresses: *const usize,
    len: usize,
}

pub struct HashBasedMemoryComparator {}

impl HashBasedMemoryComparator {
    pub fn new() -> Self {
        Self {}
    }
}

fn compute_page_hash(
    page_addresses: &[Range<usize>],
    mut process: Process<Stopped>,
) -> Result<WithProcess<Stopped, u64>> {
    let iovecs = page_addresses
        .iter()
        .map(|range| unsafe {
            IoSlice::new(std::slice::from_raw_parts(
                range.start as *const u8,
                range.end - range.start,
            ))
        })
        .collect::<Vec<_>>();

    let len = (iovecs.len() * std::mem::size_of::<IoSlice>()).next_multiple_of(*PAGESIZE);

    let addr;
    WithProcess(process, addr) = process.mmap(
        0,
        len,
        ProtFlags::PROT_READ | ProtFlags::PROT_WRITE,
        MapFlags::MAP_PRIVATE | MapFlags::MAP_ANONYMOUS,
    )?;
    let addr = addr?;

    process.write_values(addr.into(), &iovecs)?;

    let hasher_args = HasherArgs {
        addresses: addr as *const usize,
        len: iovecs.len(),
    };

    let binary = include_bytes!(concat!(env!("OUT_DIR"), "/hasher.bin"));

    let hash: u64;
    WithProcess(process, hash) = unsafe { inject_and_run(binary, &hasher_args, process)? };

    let result;
    WithProcess(process, result) = process.munmap(addr, len)?;
    result?;

    Ok(WithProcess(process, hash))
}

impl MemoryComparator for HashBasedMemoryComparator {
    fn compare_memory(
        &self,
        page_addresses: &[Range<usize>],
        chk_process: Process<Stopped>,
        ref_process: Process<Stopped>,
    ) -> Result<(Process<Stopped>, Process<Stopped>, MemoryComparsionResult)> {
        let WithProcess(chk_process, chk_hash) = compute_page_hash(page_addresses, chk_process)?;
        debug!("Checker hash: {:#0x}", chk_hash);

        let WithProcess(ref_process, ref_hash) = compute_page_hash(page_addresses, ref_process)?;
        debug!("Reference hash: {:#0x}", ref_hash);

        let ret = if chk_hash == ref_hash {
            MemoryComparsionResult::Pass
        } else {
            MemoryComparsionResult::Fail {
                first_mismatch: None,
            }
        };

        Ok((chk_process, ref_process, ret))
    }
}

impl Module for HashBasedMemoryComparator {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_memory_comparator(self);
    }
}
