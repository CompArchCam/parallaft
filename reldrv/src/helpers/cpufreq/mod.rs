mod cpuinfo;
pub mod dynamic;
pub mod fixed;
mod governor;
mod utils;

pub use governor::CpuFreqGovernor;

#[derive(Debug, Clone, Default)]
pub enum CpuFreqScalerType {
    #[default]
    Null,
    Fixed(CpuFreqGovernor),
    Dynamic,
}
