use clap::ValueEnum;

pub mod hasher;
pub mod simple;

#[derive(Debug, Clone, Copy, PartialEq, Eq, ValueEnum, Default)]
pub enum MemoryComparatorType {
    #[default]
    Hasher,
    Simple,
    None,
}
