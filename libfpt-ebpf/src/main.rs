// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)

use core::time::Duration;
use std::os::fd::AsFd;
use std::os::fd::AsRawFd;

use anyhow::bail;
use anyhow::Result;
use clap::Parser;
use libbpf_rs::skel::OpenSkel;
use libbpf_rs::skel::Skel;
use libbpf_rs::skel::SkelBuilder;
use libbpf_rs::MapFlags;

use libbpf_rs::RingBufferBuilder;

mod fpt {
    include!(concat!(env!("OUT_DIR"), "/fpt.skel.rs"));
}

use fpt::*;

/// Trace high run queue latency
#[derive(Debug, Parser)]
struct Command {
    /// Process PID to trace
    #[arg(default_value = "1")]
    pid: i32,
    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: 128 << 20,
        rlim_max: 128 << 20,
    };

    if unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) } != 0 {
        bail!("Failed to increase rlimit");
    }

    Ok(())
}

type Addr = u64;

fn handle_event(data: &[u8]) -> i32 {
    assert!(data.len() % std::mem::size_of::<Addr>() == 0);

    let _addrs: &[Addr] = unsafe {
        std::slice::from_raw_parts(
            data.as_ptr() as *const Addr,
            data.len() / std::mem::size_of::<Addr>(),
        )
    };

    0
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut skel_builder = FptSkelBuilder::default();
    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_skel = skel_builder.open()?;

    // Write arguments into prog
    open_skel.rodata().flags = 0;

    // Begin tracing
    let mut skel = open_skel.load()?;
    skel.attach()?;

    let ringbuf_map = libbpf_rs::MapHandle::create(
        libbpf_rs::MapType::RingBuf,
        Some("ringbuf_map"),
        0,
        0,
        16 * 1024 * 1024,
        None,
    )
    .unwrap();

    skel.maps_mut()
        .pid_map()
        .update(
            &opts.pid.to_le_bytes(),
            &ringbuf_map.as_fd().as_raw_fd().to_le_bytes(),
            MapFlags::ANY,
        )
        .unwrap();

    println!("Tracing page faults of PID {}", opts.pid);

    let mut rb_builder = RingBufferBuilder::new();

    rb_builder.add(&ringbuf_map, handle_event)?;

    let rb = rb_builder.build()?;
    loop {
        rb.poll(Duration::from_millis(100))?;
    }
}
