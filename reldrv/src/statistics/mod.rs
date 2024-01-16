use std::fmt::{Display, Formatter};

use parking_lot::Mutex;

pub mod counter;
pub mod dirty_pages;
pub mod memory;
pub mod perf;
pub mod timing;

#[macro_export]
macro_rules! statistics_list {
    ($($name:ident = $value:expr),*) => {
        Box::new(
            [
                $(
                    (::std::stringify!($name).to_owned(), Box::new($value))
                ),*
            ]
        )
    };
}

pub trait StatisticsProvider {
    fn class_name(&self) -> &'static str;

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]>;
}

pub trait StatisticValue {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result;
}

macro_rules! impl_statistic_value {
    ($($name:ident),*) => {
        $(
            impl StatisticValue for $name {
                fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
                    Display::fmt(self, f)
                }
            }
        )*
    };
}

impl_statistic_value!(u32, i32, f32, u64, i64, f64, usize, isize);

struct DisplayProxy<'i> {
    inner: &'i dyn StatisticValue,
}

impl<'i> DisplayProxy<'i> {
    pub fn new(inner: &'i dyn StatisticValue) -> Self {
        Self { inner }
    }
}

impl<'i> Display for DisplayProxy<'i> {
    fn fmt(&self, f: &mut Formatter<'_>) -> std::fmt::Result {
        StatisticValue::fmt(self.inner, f)
    }
}

pub fn as_text(stats: Box<[(String, Box<dyn StatisticValue>)]>) -> String {
    stats
        .iter()
        .map(|(k, v)| format!("{}={}", k, DisplayProxy::new(v.as_ref())))
        .collect::<Vec<String>>()
        .join("\n")
}

pub struct RunningAverage {
    data: Mutex<(f64, usize)>,
}

impl RunningAverage {
    pub fn new() -> Self {
        Self {
            data: Mutex::new((0.0, 0)),
        }
    }
    pub fn get(&self) -> f64 {
        self.data.lock().0
    }

    pub fn update(&self, value: f64) {
        let mut data = self.data.lock();
        let (avg, cnt) = &mut *data;

        *cnt += 1;
        *avg = (1.0 / *cnt as f64) * value + (1.0 - 1.0 / *cnt as f64) * *avg;
    }
}
