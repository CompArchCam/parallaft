use crate::{error::Result, process::registers::Registers};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RegisterComparsionResult {
    NoResult,
    Pass,
    Fail,
}

pub trait RegisterComparator {
    fn compare_registers(
        &self,
        chk_registers: &mut Registers,
        ref_registers: &mut Registers,
    ) -> Result<RegisterComparsionResult>;
}
