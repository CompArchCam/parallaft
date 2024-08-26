use crate::{error::Result, helpers::insn_patcher::Patch, process::state::Stopped};

use super::HandlerContext;

pub trait InstructionPatchingEventHandler: Sync {
    fn should_instruction_patched(&self, patch: &Patch, ctx: HandlerContext<Stopped>) -> bool;
    fn handle_instruction_patched(&self, patch: &Patch, ctx: HandlerContext<Stopped>)
        -> Result<()>;
    fn handle_instruction_patch_removed(
        &self,
        patch: &Patch,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()>;
}
