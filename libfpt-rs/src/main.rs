use clap::Parser;
use libfpt_rs::{FptFd, FptFlags};
use nix::unistd::Pid;
use std::io::Result;

#[derive(Debug, Parser)]
struct Command {
    /// Process PID to trace
    #[arg()]
    pid: i32,

    /// Trace buffer size
    #[arg(long, default_value_t = 1 * 1024 * 1024)]
    buffer_size: usize,

    /// Exclude non-writable VMAs?
    #[arg(short, long)]
    exclude_nonwritable_vma: bool,

    /// Allow reallocation
    #[arg(short, long)]
    allow_realloc: bool,

    /// Verbose debug output
    #[arg(short, long)]
    verbose: bool,
}

fn main() -> Result<()> {
    let opts = Command::parse();

    let mut flags = FptFlags::empty();

    flags.set(
        FptFlags::EXCLUDE_NON_WRITABLE_VMA,
        opts.exclude_nonwritable_vma,
    );

    flags.set(FptFlags::ALLOW_REALLOC, opts.allow_realloc);

    let mut fd = FptFd::new(Pid::from_raw(opts.pid), opts.buffer_size, flags, None)?;

    fd.enable()?;

    ctrlc::set_handler(move || println!("Stopping")).unwrap();

    nix::unistd::sleep(10000000);

    fd.disable()?;

    dbg!(fd.get_count()?);
    dbg!(fd.get_lost_count()?);

    Ok(())
}
