use crate::types::perf_counter::PerfCounter;

pub struct AddPerfCounter(pub Box<dyn PerfCounter>, pub Box<dyn PerfCounter>);

impl PerfCounter for AddPerfCounter {
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

        Ok(first + second)
    }
}
