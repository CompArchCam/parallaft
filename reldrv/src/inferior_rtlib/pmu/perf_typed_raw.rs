use perf_event::events::Event;
use perf_event_open_sys::bindings::perf_event_attr;

pub(super) struct TypedRaw {
    ty: u32,
    config: u64,
}

impl TypedRaw {
    pub fn new(ty: u32, config: u64) -> Self {
        Self { ty, config }
    }
}

impl Event for TypedRaw {
    fn update_attrs(self, attr: &mut perf_event_attr) {
        attr.type_ = self.ty;
        attr.config = self.config;
        attr.__bindgen_anon_3.config1 = 0;
        attr.__bindgen_anon_4.config2 = 0;
    }
}
