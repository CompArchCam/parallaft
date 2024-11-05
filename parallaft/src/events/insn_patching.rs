use crate::{error::Result, helpers::insn_patcher::Patch, process::state::Stopped};

use super::HandlerContextWithInferior;

pub trait InstructionPatchingEventHandler: Sync {
    fn should_instruction_patched(
        &self,
        patch: &Patch,
        ctx: HandlerContextWithInferior<Stopped>,
    ) -> bool;
    fn handle_instruction_patched(
        &self,
        patch: &Patch,
        ctx: HandlerContextWithInferior<Stopped>,
    ) -> Result<()>;
    fn handle_instruction_patch_removed(
        &self,
        patch: &Patch,
        ctx: HandlerContextWithInferior<Stopped>,
    ) -> Result<()>;
}
