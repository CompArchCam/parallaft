use std::{collections::HashMap, path::PathBuf};

use lazy_static::lazy_static;
use parking_lot::Mutex;
use try_insert_ext::EntryInsertExt;

use super::{Dynamic, Hardware, HardwareUnderPmu, RawUnderPmu};

lazy_static! {
    pub static ref EVENT_CACHE: EventCache = EventCache::new();
}

pub struct EventCache {
    dynamic_cache: Mutex<HashMap<(PathBuf, PathBuf), Dynamic>>,
    hardware_under_pmu_cache: Mutex<HashMap<(PathBuf, Hardware), HardwareUnderPmu>>,
    raw_under_pmu_cache: Mutex<HashMap<(PathBuf, u64), RawUnderPmu>>,
}

impl EventCache {
    pub fn new() -> Self {
        Self {
            dynamic_cache: Mutex::new(HashMap::new()),
            hardware_under_pmu_cache: Mutex::new(HashMap::new()),
            raw_under_pmu_cache: Mutex::new(HashMap::new()),
        }
    }

    pub fn dynamic(
        &self,
        pmu: impl Into<PathBuf>,
        event: impl Into<PathBuf>,
    ) -> std::io::Result<Dynamic> {
        let pmu: PathBuf = pmu.into();
        let event: PathBuf = event.into();
        self.dynamic_cache
            .lock()
            .entry((pmu.clone(), event.clone()))
            .or_try_insert_with(|| Dynamic::new(pmu, event))
            .cloned()
    }

    pub fn hardware_under_pmu(
        &self,
        pmu: impl Into<PathBuf>,
        config: Hardware,
    ) -> std::io::Result<HardwareUnderPmu> {
        let pmu: PathBuf = pmu.into();
        self.hardware_under_pmu_cache
            .lock()
            .entry((pmu.clone(), config))
            .or_try_insert_with(|| HardwareUnderPmu::new(pmu, config))
            .cloned()
    }

    pub fn raw_under_pmu(
        &self,
        pmu: impl Into<PathBuf>,
        config: u64,
    ) -> std::io::Result<RawUnderPmu> {
        let pmu: PathBuf = pmu.into();
        self.raw_under_pmu_cache
            .lock()
            .entry((pmu.clone(), config))
            .or_try_insert_with(|| RawUnderPmu::new(pmu, config))
            .cloned()
    }
}
