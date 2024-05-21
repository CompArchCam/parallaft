pub mod linux;
pub mod pmu_type;
pub mod sub;

use std::io;

use clap::ValueEnum;
use nix::sys::signal::Signal;

use crate::{error::Result, process::Process};

pub trait PerfCounter: Send + Sync {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
    fn reset(&mut self) -> io::Result<()>;
    fn read(&mut self) -> io::Result<u64>;
}

pub trait PerfCounterCheckInterrupt {
    fn is_interrupt(&self, signal: Signal, process: &Process) -> Result<bool>;
}

pub trait PerfCounterWithInterrupt: PerfCounter + PerfCounterCheckInterrupt {}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Default, ValueEnum)]
pub enum BranchCounterType {
    #[default]
    AllExclFar,
    Cond,
    CondTaken,
}
