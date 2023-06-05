use std::io::IoSlice;
use std::mem::size_of;
use std::slice;
use std::{io::IoSliceMut, mem::MaybeUninit};

use nix::errno::Errno;
use nix::sys::uio::{process_vm_readv, process_vm_writev, RemoteIoVec};
use nix::unistd::Pid;
use nix::Result;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub enum CliRole {
    #[default]
    Main = 0,
    Checker = 1,
    Nop = 2,
}

const MAGIC: u32 = 0xfbb59834;

#[repr(C)]
#[derive(Debug, Default, Clone, Copy)]
pub struct CliControl {
    magic: u32,
    pub role: CliRole,
    interval_tsc: u64,
    last_tsc: u64,
    pub counter: i32,
}

pub fn read(src: Pid, base_address: usize) -> Result<CliControl> {
    let mut ctl = MaybeUninit::<CliControl>::uninit();

    process_vm_readv(
        src,
        &mut [IoSliceMut::new(unsafe {
            slice::from_raw_parts_mut(ctl.as_mut_ptr() as *mut _, size_of::<CliControl>())
        })],
        &[RemoteIoVec {
            base: base_address,
            len: size_of::<CliControl>(),
        }],
    )?;

    let ctl = unsafe { ctl.assume_init() };

    if ctl.magic != MAGIC {
        return Err(Errno::EPROTO);
    }

    Ok(ctl)
}

pub fn write(ctl: &CliControl, dst: Pid, base_address: usize) -> Result<()> {
    process_vm_writev(
        dst,
        &[IoSlice::new(unsafe {
            slice::from_raw_parts(ctl as *const _ as *const u8, size_of::<CliControl>())
        })],
        &[RemoteIoVec {
            base: base_address,
            len: size_of::<CliControl>(),
        }],
    )?;

    Ok(())
}
