use std::fmt::Display;

use clap::ValueEnum;

pub mod entire_program;
pub mod fixed_interval;

#[derive(Debug, PartialEq, Eq, Clone, Copy, ValueEnum, Default)]
pub enum ReferenceType {
    #[default]
    Instructions,
    Cycles,
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

#[derive(Debug, PartialEq, Eq, Clone, Copy, ValueEnum, Default)]
pub enum SlicerType {
    #[default]
    Null,
    FixedInterval,
    EntireProgram,
}
