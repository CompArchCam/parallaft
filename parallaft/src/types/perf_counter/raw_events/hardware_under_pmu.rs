use std::path::Path;

use perf_event::events::{Event, Hardware};

use crate::types::perf_counter::cpu_info::pmu::PMUS;

use super::get_pmu_type;

#[derive(Debug, Clone, Copy)]
pub struct HardwareUnderPmu {
    config: u64,
}

impl HardwareUnderPmu {
    pub fn new(pmu: impl AsRef<Path>, config: Hardware) -> std::io::Result<Self> {
        if PMUS.len() > 1 {
            Ok(Self {
                config: <Hardware as Into<u64>>::into(config) | ((get_pmu_type(pmu)? as u64) << 32),
            })
        } else {
            Ok(Self {
                config: <Hardware as Into<u64>>::into(config),
            })
        }
    }
}

impl Event for HardwareUnderPmu {
    fn update_attrs(self, attr: &mut perf_event_open_sys::bindings::perf_event_attr) {
        attr.type_ = perf_event_open_sys::bindings::PERF_TYPE_HARDWARE;
        attr.config = self.config;
    }
}
