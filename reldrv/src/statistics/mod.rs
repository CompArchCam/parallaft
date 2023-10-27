use std::fmt::Display;

pub mod counter;
pub mod dirty_pages;
pub mod perf;
pub mod timing;

pub trait Statistics {
    fn class_name(&self) -> &'static str;

    fn statistics(&self) -> Box<[(&'static str, Value)]>;
}

#[derive(Debug, Clone, Copy)]
pub enum Value {
    Float(f64),
    Int(u64),
}

impl Display for Value {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Value::Float(v) => v.fmt(f),
            Value::Int(v) => v.fmt(f),
        }
    }
}

pub struct StatisticsSet<'a> {
    stats: Vec<&'a dyn Statistics>,
}

impl<'a> StatisticsSet<'a> {
    pub fn new(stats: Vec<&'a dyn Statistics>) -> Self {
        Self { stats }
    }

    pub fn all_statistics(&self) -> Box<[(String, Value)]> {
        let mut s = Vec::new();

        for &ss in &self.stats {
            let mut stats_data = ss
                .statistics()
                .into_iter()
                .map(|(stat_name, value)| (format!("{}.{}", ss.class_name(), stat_name), *value))
                .collect();

            s.append(&mut stats_data);
        }

        s.into_boxed_slice()
    }

    pub fn as_text(&self) -> String {
        self.all_statistics()
            .iter()
            .map(|(k, v)| format!("{}={}", k, v))
            .collect::<Vec<String>>()
            .join("\n")
    }
}
