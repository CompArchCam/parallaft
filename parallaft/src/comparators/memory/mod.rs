use clap::ValueEnum;
use serde::{Deserialize, Serialize};

pub mod hasher;
pub mod simple;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default, Serialize, Deserialize)]
pub enum MemoryComparatorType {
    #[default]
    Hasher,
    Simple,
    None,
}
