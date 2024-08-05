use crate::{error::Result, helpers::insn_patcher::Patch};

use super::HandlerContext;

pub trait InstructionPatchingEventHandler: Sync {
    fn should_instruction_patched(&self, patch: &Patch, ctx: HandlerContext) -> bool;
    fn handle_instruction_patched(&self, patch: &Patch, ctx: HandlerContext) -> Result<()>;
    fn handle_instruction_patch_removed(&self, patch: &Patch, ctx: HandlerContext) -> Result<()>;
}
