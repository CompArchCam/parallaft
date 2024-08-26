use std::ops::Range;

use crate::{
    error::Result,
    process::{registers::Registers, state::Stopped, Process},
};

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub enum RegisterComparsionResult {
    NoResult,
    Pass,
    Fail,
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MemoryComparsionResult {
    Pass,
    Fail {
        mismatching_pages: Option<Vec<usize>>,
    },
}

pub trait RegisterComparator {
    fn compare_registers(
        &self,
        chk_registers: &mut Registers,
        ref_registers: &mut Registers,
    ) -> Result<RegisterComparsionResult>;
}

pub trait MemoryComparator: Sync {
    fn compare_memory(
        &self,
        page_addresses: &[Range<usize>],
        chk_process: Process<Stopped>,
        ref_process: Process<Stopped>,
    ) -> Result<(Process<Stopped>, Process<Stopped>, MemoryComparsionResult)>;
}
