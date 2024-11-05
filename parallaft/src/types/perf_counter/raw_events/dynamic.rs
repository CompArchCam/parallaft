use std::path::Path;

use perf_event::events::Event;

#[derive(Debug, Clone, Copy)]
pub struct Dynamic {
    inner: perf_event::events::Dynamic,
}

impl Dynamic {
    pub fn new(pmu: impl AsRef<Path>, event: impl AsRef<Path>) -> std::io::Result<Self> {
        let mut builder = perf_event::events::DynamicBuilder::new(pmu)?;

        builder.event(event)?;
        let params: Vec<String> = builder.params().map(str::to_string).collect();

        for param in params {
            builder.field(&param, 0)?;
        }

        Ok(Self {
            inner: builder.build()?,
        })
    }
}

impl Event for Dynamic {
    fn update_attrs(self, attr: &mut perf_event_open_sys::bindings::perf_event_attr) {
        self.inner.update_attrs(attr)
    }
}
