use nix::unistd::Pid;
use perf_event::SampleSkid;

use crate::{impl_perf_counter, impl_perf_counter_with_interrupt};

use super::expr::BasePerfCounterWithInterrupt;

pub struct Breakpoint {
    counter: BasePerfCounterWithInterrupt,
}

impl Breakpoint {
    pub fn new(pid: Pid, ip: usize) -> std::io::Result<Self> {
        Ok(Self {
            counter: BasePerfCounterWithInterrupt::new(
                perf_event::events::Breakpoint::execute(ip as _),
                pid,
                true,
                1,
                SampleSkid::Arbitrary,
            )?,
        })
    }
}

impl_perf_counter!(Breakpoint, counter);
impl_perf_counter_with_interrupt!(Breakpoint, counter);
