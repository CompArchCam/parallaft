use super::Process;
use crate::error::Result;
use log::info;

impl Process {
    pub fn unwind(&self) -> Result<()> {
        let uw_ptrace_state = unwind::PTraceState::new(self.pid.as_raw() as _).unwrap();
        let uw_addr_space =
            unwind::AddressSpace::new(unwind::Accessors::ptrace(), unwind::Byteorder::DEFAULT)
                .unwrap();

        let mut uw_cursor = unwind::Cursor::remote(&uw_addr_space, &uw_ptrace_state).unwrap();

        info!("Backtrace for PID {}", self.pid);

        loop {
            let ip = uw_cursor.register(unwind::RegNum::IP).unwrap();

            match (uw_cursor.procedure_info(), uw_cursor.procedure_name()) {
                (Ok(ref info), Ok(ref name)) if ip == info.start_ip() + name.offset() => {
                    info!(
                        "{:#016x} - {} ({:#016x}) + {:#x}",
                        ip,
                        name.name(),
                        info.start_ip(),
                        name.offset(),
                    );
                }
                _ => info!("{:#016x} - ????", ip),
            }

            if uw_cursor.step().unwrap() {
                break;
            }
        }

        Ok(())
    }
}
