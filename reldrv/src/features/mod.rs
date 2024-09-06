pub mod dirty_page_userspace_scan;
pub mod pagemap_scan;

use std::fmt::Display;

use colored::Colorize;
use lazy_init::Lazy;
use lazy_static::lazy_static;
use nix::errno::Errno;

use self::{
    dirty_page_userspace_scan::{KPAGECOUNT_FEATURE, SOFT_DIRTY_FEATURE},
    pagemap_scan::{PAGEMAP_SCAN_SOFT_DIRTY_FEATURE, PAGEMAP_SCAN_UNIQUE_FEATURE},
};

use crate::error::Error;

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum FeatureAvailability {
    Ok,
    RequiresPrivilege,
    Unavailable,
}

impl Display for FeatureAvailability {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            FeatureAvailability::Ok => "ok".green().fmt(f),
            FeatureAvailability::RequiresPrivilege => "requires privilege".yellow().fmt(f),
            FeatureAvailability::Unavailable => "unavailable".red().fmt(f),
        }
    }
}

impl<T> From<crate::error::Result<T>> for FeatureAvailability {
    fn from(result: crate::error::Result<T>) -> Self {
        match result {
            Ok(_) => FeatureAvailability::Ok,
            Err(Error::Nix(Errno::EPERM)) => FeatureAvailability::RequiresPrivilege,
            Err(_) => FeatureAvailability::Unavailable,
        }
    }
}

impl FeatureAvailability {
    pub fn is_ok(&self) -> bool {
        self == &FeatureAvailability::Ok
    }
}

pub trait Feature: Sync {
    fn name(&self) -> String;
    fn is_available(&self) -> FeatureAvailability;
}

impl Display for dyn Feature {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}: {}", self.name(), self.is_available())
    }
}

pub struct Cached<T: Feature> {
    inner: T,
    avail: Lazy<FeatureAvailability>,
}

impl<T: Feature> Cached<T> {
    fn new(inner: T) -> Self {
        Self {
            inner,
            avail: Lazy::new(),
        }
    }
}

impl<T: Feature> Feature for Cached<T> {
    fn is_available(&self) -> FeatureAvailability {
        *self.avail.get_or_create(|| self.inner.is_available())
    }

    fn name(&self) -> String {
        self.inner.name()
    }
}

lazy_static! {
    pub static ref FEATURES: Vec<Box<&'static dyn Feature>> = vec![
        Box::new(&*PAGEMAP_SCAN_SOFT_DIRTY_FEATURE),
        Box::new(&*PAGEMAP_SCAN_UNIQUE_FEATURE),
        Box::new(&*KPAGECOUNT_FEATURE),
        Box::new(&*SOFT_DIRTY_FEATURE),
    ];
}

pub fn show_features() {
    FEATURES.iter().for_each(|f| {
        println!("{}", f);
    });
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_show_features() {
        show_features();
    }
}
