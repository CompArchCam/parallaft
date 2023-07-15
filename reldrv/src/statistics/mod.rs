use std::fmt::Display;

pub mod cache;
pub mod counter;
pub mod dirty_pages;
pub mod timing;

pub trait Statistics {
    fn name(&self) -> &'static str;

    fn statistics(&self) -> Box<[(&'static str, Value)]>;
}

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

    pub fn all_statistics(&self) -> Box<[(&'static str, Value)]> {
        let mut s = Vec::new();

        for ss in &self.stats {
            s.append(&mut ss.statistics().into_vec())
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
