mod cpuinfo;
pub mod dynamic;
pub mod fixed;
mod governor;
mod utils;

pub use governor::CpuFreqGovernor;
use serde::{Deserialize, Serialize};

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub enum CpuFreqScalerType {
    #[default]
    Null,
    Fixed(CpuFreqGovernor),
    Dynamic,
}
