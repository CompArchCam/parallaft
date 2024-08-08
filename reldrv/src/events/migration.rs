use super::HandlerContext;
use crate::error::Result;

pub trait MigrationHandler: Sync {
    /// Called when a checker process is migrated to a new CPU set.
    /// # States
    /// ctx.child should be a InferiorRefMut::Checker(checker)
    /// checker.segment.checker_status is CheckerStatus::Executing { cpu_set, .. } where cpu_set is the new CPU set.
    fn handle_checker_migration(&self, ctx: HandlerContext) -> Result<()>;
}
