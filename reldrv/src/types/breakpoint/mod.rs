mod hw;
mod sw;

use crate::{error::Result, process::Process};
use cfg_if::cfg_if;
pub use hw::HardwareBreakpoint;
pub use sw::SoftwareBreakpoint;

pub struct BreakpointCharacteristics {
    pub needs_single_step_after_hit: bool,
    pub needs_bp_disabled_during_single_stepping: bool,
}

pub trait Breakpoint: Send + Sync {
    fn addr(&self) -> usize;
    fn enable(&mut self, process: &mut Process) -> Result<()>;
    fn disable(&mut self, process: &mut Process) -> Result<()>;
    fn is_hit(&self, process: &Process) -> Result<bool>;
    fn characteristics(&self) -> BreakpointCharacteristics {
        BreakpointCharacteristics {
            needs_bp_disabled_during_single_stepping: true,
            needs_single_step_after_hit: true,
        }
    }
}

pub fn breakpoint(
    #[allow(unused_variables)] process: &mut Process,
    pc: usize,
) -> Result<Box<dyn Breakpoint>> {
    cfg_if! {
        if #[cfg(target_arch = "x86_64")] {
            Ok(Box::new(HardwareBreakpoint::new(process.pid, pc)?))
        }
        else {
            Ok(Box::new(SoftwareBreakpoint::new(process, pc)?))
        }
    }
}
