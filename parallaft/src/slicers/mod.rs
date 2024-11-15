use std::fmt::Display;

use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub mod dynamic;
pub mod entire_program;
pub mod fixed_interval;

#[derive(Debug, PartialEq, Eq, Clone, Copy, ValueEnum, Serialize, Deserialize)]
pub enum ReferenceType {
    Instructions,
    Cycles,
}

impl Default for ReferenceType {
    fn default() -> Self {
        if cfg!(target_arch = "x86_64") {
            // On x86_64, we cannot use cycles because it may split
            // partially-executed rep-prefixed instructions, which our exec
            // point replay mechanism cannot handle yet.
            Self::Instructions
        } else {
            Self::Cycles
        }
    }
}

impl Display for ReferenceType {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Instructions => write!(f, "instructions"),
            Self::Cycles => write!(f, "cycles"),
        }
    }
}

impl Into<perf_event::events::Hardware> for ReferenceType {
    fn into(self) -> perf_event::events::Hardware {
        match self {
            Self::Instructions => perf_event::events::Hardware::INSTRUCTIONS,
            Self::Cycles => perf_event::events::Hardware::CPU_CYCLES,
        }
    }
}

#[derive(Debug, PartialEq, Eq, Clone, Copy, ValueEnum, Default, Serialize, Deserialize)]
pub enum SlicerType {
    #[default]
    Null,
    FixedInterval,
    EntireProgram,
    Dynamic,
}
