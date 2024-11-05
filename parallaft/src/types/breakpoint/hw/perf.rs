use nix::unistd::Pid;
use perf_event::SampleSkid;

use crate::{
    error::Result,
    process::{state::Stopped, Process},
    types::{
        breakpoint::{Breakpoint, BreakpointCharacteristics},
        perf_counter::{
            symbolic_events::expr::BasePerfCounterWithInterrupt, PerfCounter,
            PerfCounterWithInterrupt,
        },
    },
};

pub struct HardwareBreakpoint {
    counter: BasePerfCounterWithInterrupt,
    addr: usize,
}

impl HardwareBreakpoint {
    pub fn new(pid: Pid, addr: usize, size: usize, watch: bool) -> std::io::Result<Self> {
        let counter = BasePerfCounterWithInterrupt::new(
            if watch {
                perf_event::events::Breakpoint::write(addr as _, size as _)
            } else {
                perf_event::events::Breakpoint::execute(addr as _)
            },
            pid,
            true,
            1,
            SampleSkid::RequestZero,
        )?;
        Ok(Self { counter, addr })
    }
}

impl Breakpoint for HardwareBreakpoint {
    fn addr(&self) -> usize {
        self.addr
    }

    fn enable(&mut self, _process: &mut Process<Stopped>) -> Result<()> {
        self.counter.enable()?;
        Ok(())
    }

    fn disable(&mut self, _process: &mut Process<Stopped>) -> Result<()> {
        self.counter.disable()?;
        Ok(())
    }

    fn is_hit(&self, process: &Process<Stopped>) -> Result<bool> {
        self.counter.is_interrupt(&process.get_siginfo()?)
    }

    fn characteristics(&self) -> BreakpointCharacteristics {
        BreakpointCharacteristics {
            needs_bp_disabled_during_single_stepping: false,
            needs_single_step_after_hit: false,
        }
    }
}
