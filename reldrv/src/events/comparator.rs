use std::{fmt::Display, ops::Range};

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

#[derive(Debug, PartialEq, Eq, Clone, Copy)]
pub struct MemoryMismatch {
    pub addr: usize,
    pub data1: u64,
    pub data2: u64,
}

impl Display for MemoryMismatch {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(
            f,
            "Memory mismatch at {:#0x}: {:#0x} != {:#0x}",
            self.addr, self.data1, self.data2
        )
    }
}

#[derive(Debug, PartialEq, Eq, Clone)]
pub enum MemoryComparsionResult {
    Pass,
    Fail {
        first_mismatch: Option<MemoryMismatch>,
    },
}

impl Display for MemoryComparsionResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            MemoryComparsionResult::Pass => write!(f, "Memory is equal"),
            MemoryComparsionResult::Fail { first_mismatch } => {
                if let Some(mismatch) = first_mismatch {
                    write!(f, "{}", mismatch)
                } else {
                    write!(f, "Memory mismatch")
                }
            }
        }
    }
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
