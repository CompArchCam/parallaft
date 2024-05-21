use super::{PerfCounter, PerfCounterCheckInterrupt, PerfCounterWithInterrupt};

pub struct SubPerfCounter<C: PerfCounter + PerfCounterCheckInterrupt, T: PerfCounter>(pub C, pub T);

impl<C: PerfCounter + PerfCounterCheckInterrupt, T: PerfCounter> PerfCounter
    for SubPerfCounter<C, T>
{
    fn enable(&mut self) -> std::io::Result<()> {
        self.0.enable()?;
        self.1.enable()?;
        Ok(())
    }

    fn disable(&mut self) -> std::io::Result<()> {
        self.0.disable()?;
        self.1.disable()?;
        Ok(())
    }

    fn reset(&mut self) -> std::io::Result<()> {
        self.0.reset()?;
        self.1.reset()?;
        Ok(())
    }

    fn read(&mut self) -> std::io::Result<u64> {
        let first = self.0.read()?;
        let second = self.1.read()?;

        Ok(first - second)
    }
}

impl<C: PerfCounter + PerfCounterCheckInterrupt, T: PerfCounter> PerfCounterCheckInterrupt
    for SubPerfCounter<C, T>
{
    fn is_interrupt(
        &self,
        signal: nix::sys::signal::Signal,
        process: &crate::process::Process,
    ) -> crate::error::Result<bool> {
        self.0.is_interrupt(signal, process)
    }
}

impl<C: PerfCounter + PerfCounterCheckInterrupt, T: PerfCounter> PerfCounterWithInterrupt
    for SubPerfCounter<C, T>
{
}
