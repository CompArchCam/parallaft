use nix::unistd::Pid;
use perf_event::events::Event;

use crate::types::perf_counter::{PerfCounter, PerfCounterWithInterrupt};

use super::Target;

pub struct BasePerfCounter(perf_event::Counter);

impl BasePerfCounter {
    pub fn new<E>(event: E, target: Target, pinned: bool) -> std::io::Result<Self>
    where
        E: Event,
    {
        let mut builder = perf_event::Builder::new(event);
        let mut counter = builder.pinned(pinned).enabled(true).exclude_guest(true);

        counter = match target {
            Target::Pid(pid) => counter.observe_pid(pid.as_raw() as _),
            Target::Cpu(cpu) => counter.any_pid().include_kernel().include_hv().one_cpu(cpu),
        };

        Ok(Self(counter.build()?))
    }
}

impl PerfCounter for BasePerfCounter {
    fn enable(&mut self) -> std::io::Result<()> {
        self.0.enable()
    }

    fn disable(&mut self) -> std::io::Result<()> {
        self.0.disable()
    }

    fn reset(&mut self) -> std::io::Result<()> {
        self.0.reset()
    }

    fn read(&mut self) -> std::io::Result<u64> {
        self.0.read()
    }
}

pub struct BasePerfCounterWithInterrupt {
    counter: perf_event::Counter,
    sig_data: u64,
}

impl BasePerfCounterWithInterrupt {
    pub fn new<E>(
        event: E,
        pid: Pid,
        pinned: bool,
        irq_period: u64,
        sample_skid: perf_event::SampleSkid,
    ) -> std::io::Result<Self>
    where
        E: Event,
    {
        let mut builder = perf_event::Builder::new(event);

        let sig_data = rand::random();

        let counter = builder
            .pinned(pinned)
            .enabled(true)
            .observe_pid(pid.as_raw() as _)
            .wakeup_events(1)
            .sample_period(irq_period)
            .sigtrap(true)
            .sig_data(sig_data)
            .precise_ip(sample_skid)
            .remove_on_exec(true)
            .exclude_guest(true)
            .build()?;

        Ok(Self { counter, sig_data })
    }
}

impl PerfCounter for BasePerfCounterWithInterrupt {
    fn enable(&mut self) -> std::io::Result<()> {
        self.counter.enable()
    }

    fn disable(&mut self) -> std::io::Result<()> {
        self.counter.disable()
    }

    fn reset(&mut self) -> std::io::Result<()> {
        self.counter.reset()
    }

    fn read(&mut self) -> std::io::Result<u64> {
        self.counter.read()
    }
}

impl PerfCounterWithInterrupt for BasePerfCounterWithInterrupt {
    fn is_interrupt(&self, sig_info: &nix::libc::siginfo_t) -> crate::error::Result<bool> {
        Ok(sig_info.si_signo == nix::libc::SIGTRAP
            && sig_info.si_code == 0x6 /* TRAP_PERF */
            && unsafe { sig_info.si_value().sival_ptr as u64 } == self.sig_data)
    }
}
