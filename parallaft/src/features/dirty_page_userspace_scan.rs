use lazy_static::lazy_static;

use crate::{
    features::Cached,
    process::{dirty_pages::PageFlagType, Process},
};

use super::{Feature, FeatureAvailability};

pub struct DirtyPageUserspaceScanFeature {
    pageflag_type: PageFlagType,
}

impl DirtyPageUserspaceScanFeature {
    fn new(pageflag_type: PageFlagType) -> Self {
        Self { pageflag_type }
    }
}

impl Feature for DirtyPageUserspaceScanFeature {
    fn name(&self) -> String {
        format!("dirty page tracking: userspace scan {}", self.pageflag_type)
    }

    fn is_available(&self) -> FeatureAvailability {
        let process = Process::shell();

        let result = process.get_dirty_pages_userspace_scan(self.pageflag_type, &[]);

        if let Ok(result) = &result {
            if result.len() == 0 {
                return FeatureAvailability::Unavailable;
            }
        }

        result.into()
    }
}

lazy_static! {
    pub static ref KPAGECOUNT_FEATURE: Cached<DirtyPageUserspaceScanFeature> = Cached::new(
        DirtyPageUserspaceScanFeature::new(PageFlagType::KPageCountEqualsOne)
    );
    pub static ref SOFT_DIRTY_FEATURE: Cached<DirtyPageUserspaceScanFeature> =
        Cached::new(DirtyPageUserspaceScanFeature::new(PageFlagType::SoftDirty));
}
