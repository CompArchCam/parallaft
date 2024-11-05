use std::path::Path;

use perf_event::events::Event;

use super::get_pmu_type;

#[derive(Debug, Clone, Copy)]
pub struct RawUnderPmu {
    ty: u32,
    config: u64,
}

impl RawUnderPmu {
    pub fn new(pmu: impl AsRef<Path>, config: u64) -> std::io::Result<Self> {
        Ok(Self {
            ty: get_pmu_type(pmu)?,
            config,
        })
    }
}

impl Event for RawUnderPmu {
    fn update_attrs(self, attr: &mut perf_event_open_sys::bindings::perf_event_attr) {
        attr.type_ = self.ty;
        attr.config = self.config;
        attr.__bindgen_anon_3.config1 = 0;
        attr.__bindgen_anon_4.config2 = 0;
    }
}
