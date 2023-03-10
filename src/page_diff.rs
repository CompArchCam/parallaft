use std::io::IoSliceMut;

use log::{info, trace};
use nix::sys::uio::{process_vm_readv, RemoteIoVec};
use nix::unistd::sysconf;
use nix::unistd::Pid;
use pretty_hex::PrettyHex;

use crate::utils::format_vec_pointer;

#[derive(Debug, PartialEq, Eq)]
pub enum PageDiffResult {
    Equal,
    PageSetDiff,
    PageDataDiff,
}

pub fn page_diff(
    p1: Pid,
    p2: Pid,
    pages_p1: &Vec<u64>,
    pages_p2: &Vec<u64>,
) -> Result<PageDiffResult, ()> {
    if pages_p1 != pages_p2 {
        info!("Page sets do not match");
        return Ok(PageDiffResult::PageSetDiff);
    }

    let block_size = 32;
    let page_size = sysconf(nix::unistd::SysconfVar::PAGE_SIZE)
        .unwrap()
        .unwrap() as usize;
    let mut buf_p1 = vec![0_u8; block_size * page_size];
    let mut buf_p2 = vec![0_u8; block_size * page_size];

    let remote_iovs: Vec<RemoteIoVec> = pages_p1
        .into_iter()
        .map(|p| RemoteIoVec {
            base: *p as _,
            len: page_size,
        })
        .collect();

    for remote_iov in remote_iovs.chunks(block_size) {
        let local_iov_p1 = IoSliceMut::new(&mut buf_p1[..remote_iov.len() * page_size]);
        let local_iov_p2 = IoSliceMut::new(&mut buf_p2[..remote_iov.len() * page_size]);

        process_vm_readv(p1, &mut [local_iov_p1], remote_iov)
            .expect("failed to read memory from process 1");
        process_vm_readv(p2, &mut [local_iov_p2], remote_iov)
            .expect("failed to read memory from process 2");

        trace!(
            "page data p1@{:p}:\n{:?}",
            remote_iov[0].base as *const u8,
            &buf_p1[..remote_iov.len() * page_size].hex_dump()
        );
        trace!(
            "page data p2@{:p}:\n{:?}",
            remote_iov[0].base as *const u8,
            &buf_p2[..remote_iov.len() * page_size].hex_dump()
        );

        if buf_p1 != buf_p2 {
            let pages: Vec<u64> = remote_iov.iter().map(|i| i.base as _).collect();
            info!("Page data does not match: {}", format_vec_pointer(&pages));
            return Ok(PageDiffResult::PageDataDiff);
        }
    }

    Ok(PageDiffResult::Equal)
}
