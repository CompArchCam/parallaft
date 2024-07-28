mod cache;
mod dynamic;
mod hardware_under_pmu;
mod raw_under_pmu;

pub use cache::{EventCache, EVENT_CACHE};
pub use dynamic::Dynamic;
pub use hardware_under_pmu::HardwareUnderPmu;
pub use perf_event::events::Hardware;
pub use raw_under_pmu::RawUnderPmu;

use std::path::{Path, PathBuf};

use super::EVENT_SOURCE_DEVICES_ROOT;

pub(self) fn get_pmu_type(pmu: impl AsRef<Path>) -> std::io::Result<u32> {
    let mut path = PathBuf::from(EVENT_SOURCE_DEVICES_ROOT);
    path.push(pmu);
    path.push("type");

    let ty: u32 = match std::fs::read_to_string(&path)?.trim().parse() {
        Ok(ty) => ty,
        Err(_) => return Err(std::io::Error::other("Failed to parse PMU type"))?,
    };

    Ok(ty)
}
