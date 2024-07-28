pub mod cpu_info;
// pub mod linux;
pub mod raw_events;
pub mod symbolic_events;

use std::{collections::HashMap, io};

use clap::ValueEnum;
use cpu_info::{detect_all_cpu_info, CpuInfo};
use lazy_static::lazy_static;

use crate::error::Result;

pub const EVENT_SOURCE_DEVICES_ROOT: &'static str = "/sys/bus/event_source/devices";

lazy_static! {
    pub static ref CPU_INFO_MAP: HashMap<usize, CpuInfo> = detect_all_cpu_info();
}

pub trait PerfCounter: Send + Sync {
    fn enable(&mut self) -> io::Result<()>;
    fn disable(&mut self) -> io::Result<()>;
    fn reset(&mut self) -> io::Result<()>;
    fn read(&mut self) -> io::Result<u64>;
}

#[macro_export]
macro_rules! impl_perf_counter {
    ($t:ty, $field:ident) => {
        impl $crate::types::perf_counter::PerfCounter for $t {
            fn enable(&mut self) -> std::io::Result<()> {
                self.$field.enable()
            }

            fn disable(&mut self) -> std::io::Result<()> {
                self.$field.disable()
            }

            fn reset(&mut self) -> std::io::Result<()> {
                self.$field.reset()
            }

            fn read(&mut self) -> std::io::Result<u64> {
                self.$field.read()
            }
        }
    };
}

pub trait PerfCounterWithInterrupt: PerfCounter {
    fn is_interrupt(&self, sig_info: &nix::libc::siginfo_t) -> Result<bool>;
}

#[macro_export]
macro_rules! impl_perf_counter_with_interrupt {
    ($t:ty, $field:ident) => {
        impl $crate::types::perf_counter::PerfCounterWithInterrupt for $t {
            fn is_interrupt(&self, sig_info: &nix::libc::siginfo_t) -> $crate::error::Result<bool> {
                self.$field.is_interrupt(sig_info)
            }
        }
    };
}
