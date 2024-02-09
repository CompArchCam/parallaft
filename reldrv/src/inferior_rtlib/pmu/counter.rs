use nix::unistd::Pid;
use perf_event::Counter;
use std::io;

pub(super) trait PmuCounter {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
    fn reset(&mut self) -> io::Result<()>;
    fn read(&mut self) -> io::Result<u64>;
}

pub(super) struct PmuCounterSingle {
    counter: Counter,
}

impl PmuCounterSingle {
    pub fn new(counter: Counter) -> Self {
        Self { counter }
    }
}

impl PmuCounter for PmuCounterSingle {
    fn enable(&mut self) -> io::Result<()> {
        self.counter.enable()
    }

    fn disable(&mut self) -> io::Result<()> {
        self.counter.disable()
    }

    fn reset(&mut self) -> io::Result<()> {
        self.counter.reset()
    }

    fn read(&mut self) -> io::Result<u64> {
        self.counter.read()
    }
}

pub(super) struct PmuCounterDiff {
    counter1: Box<dyn PmuCounter + Send>,
    counter2: Box<dyn PmuCounter + Send>,
}

impl PmuCounterDiff {
    pub fn new(counter1: Box<dyn PmuCounter + Send>, counter2: Box<dyn PmuCounter + Send>) -> Self {
        Self { counter1, counter2 }
    }
}

impl PmuCounter for PmuCounterDiff {
    fn enable(&mut self) -> io::Result<()> {
        self.counter1.enable()?;
        self.counter2.enable()?;
        Ok(())
    }

    fn disable(&mut self) -> io::Result<()> {
        self.counter1.disable()?;
        self.counter2.disable()?;
        Ok(())
    }

    fn reset(&mut self) -> io::Result<()> {
        self.counter1.reset()?;
        self.counter2.reset()?;
        Ok(())
    }

    fn read(&mut self) -> io::Result<u64> {
        Ok(self.counter1.read()? - self.counter2.read()?)
    }
}

pub(super) fn perf_counter<E>(
    event: E,
    pid: Pid,
    irq_cfg: Option<(u64, perf_event::SampleSkid)>,
) -> Box<PmuCounterSingle>
where
    E: perf_event::events::Event,
{
    let mut builder = perf_event::Builder::new(event);
    let mut counter = builder
        .observe_pid(pid.as_raw() as _)
        .pinned(true)
        .enabled(true);

    if let Some((irq_period, sample_skid)) = irq_cfg {
        counter = counter
            .wakeup_events(1)
            .sample_period(irq_period)
            .sigtrap(true)
            .precise_ip(sample_skid)
            .remove_on_exec(true);
    }

    Box::new(PmuCounterSingle::new(counter.build().expect(
        "Failed to initialise perf counter. Your hardware may not support it.",
    )))
}
