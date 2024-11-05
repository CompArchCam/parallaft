use lazy_static::lazy_static;

use crate::{
    features::Cached,
    process::{dirty_pages::PageCategory, Process},
};

use super::{Feature, FeatureAvailability};

pub struct PagemapScanFeature {
    category: PageCategory,
}

impl PagemapScanFeature {
    fn new(category: PageCategory) -> Self {
        Self { category }
    }
}

impl Feature for PagemapScanFeature {
    fn name(&self) -> String {
        let name = if self.category == PageCategory::SOFT_DIRTY {
            "soft dirty"
        } else if self.category == PageCategory::UNIQUE {
            "unique"
        } else {
            "[unknown]"
        };

        format!("dirty page tracking: pagemap scan {name}")
    }

    fn is_available(&self) -> FeatureAvailability {
        let process = Process::shell();

        let range = process
            .get_writable_ranges()
            .unwrap()
            .first()
            .unwrap()
            .clone();

        let result = Process::shell().pagemap_scan(
            range.start,
            range.end,
            PageCategory::empty(),
            self.category,
            PageCategory::empty(),
            self.category,
        );

        result.into()
    }
}

lazy_static! {
    pub static ref PAGEMAP_SCAN_SOFT_DIRTY_FEATURE: Cached<PagemapScanFeature> =
        Cached::new(PagemapScanFeature::new(PageCategory::SOFT_DIRTY));
    pub static ref PAGEMAP_SCAN_UNIQUE_FEATURE: Cached<PagemapScanFeature> =
        Cached::new(PagemapScanFeature::new(PageCategory::UNIQUE));
}
