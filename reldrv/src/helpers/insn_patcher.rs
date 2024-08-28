use std::{
    collections::{BTreeMap, HashMap},
    sync::Arc,
};

use log::{debug, trace, warn};
use parking_lot::Mutex;
use procfs::process::MMPermissions;
use reverie_syscalls::{Addr, MemoryAccess};

use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        hctx, insn_patching::InstructionPatchingEventHandler, memory::MemoryEventHandler,
        HandlerContext,
    },
    process::{
        memory::{Instruction, RawInstruction},
        state::Stopped,
        Process,
    },
    types::{memory_map::MemoryMap, process_id::InferiorRole},
};

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum PatchOwner {
    Mrs,
    Other(String),
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct PatchPattern {
    pub mask: RawInstruction,
    pub search: RawInstruction,
    pub replace: Instruction,
    pub owner: PatchOwner,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub struct Patch {
    pub address: usize,
    pub orig_insn: Instruction,
    pub pattern: Arc<PatchPattern>,
    pub applied: bool,
}

impl Patch {
    fn apply(&mut self, process: &mut Process<Stopped>) -> Result<()> {
        if !self.applied {
            process.insn_inject(self.pattern.replace, self.address)?;
            self.applied = true;
        }
        Ok(())
    }

    #[allow(dead_code)]
    fn revert(&mut self, process: &mut Process<Stopped>) -> Result<()> {
        if self.applied {
            process.insn_inject(self.orig_insn, self.address)?;
            self.applied = false;
        }
        Ok(())
    }
}

pub struct InstructionPatcher {
    patterns: Vec<Arc<PatchPattern>>,
    patches: Mutex<HashMap<InferiorRole, Arc<Mutex<BTreeMap<usize, Patch>>>>>,
}

impl InstructionPatcher {
    pub fn new() -> Self {
        Self {
            patterns: Vec::new(),
            patches: Mutex::new(HashMap::new()),
        }
    }

    pub fn register_pattern(&mut self, pattern: PatchPattern) {
        debug!("Registering pattern: {:?}", pattern);
        self.patterns.push(Arc::new(pattern));
    }
}

impl MemoryEventHandler for InstructionPatcher {
    fn handle_memory_map_created(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        if !map.perms.contains(MMPermissions::EXECUTE) {
            return Ok(());
        }

        if self.patterns.is_empty() {
            return Ok(());
        }

        if map.perms.contains(MMPermissions::SHARED) {
            warn!(
                "{} Shared memory map with execute permissions detected: {:?}",
                ctx.child, map
            );
        }

        let mut patches_curr = self
            .patches
            .lock()
            .entry(ctx.child.role())
            .or_insert_with(|| Arc::new(Mutex::new(BTreeMap::new())))
            .clone()
            .lock_arc();

        const BUFFER_SIZE: usize = 4096;

        let mut insn_buffer: Vec<RawInstruction> = vec![0; BUFFER_SIZE];

        for i in (map.start..map.start + map.len)
            .step_by(BUFFER_SIZE * std::mem::size_of::<RawInstruction>())
        {
            ctx.child.process_mut().read_values(
                unsafe { Addr::from_raw_unchecked(i) },
                &mut insn_buffer[..((map.start + map.len - i)
                    / std::mem::size_of::<RawInstruction>())
                .min(BUFFER_SIZE)],
            )?;

            for pattern in &self.patterns {
                for (j, insn) in insn_buffer.iter().enumerate() {
                    if insn & pattern.mask == pattern.search {
                        let address = i + j * std::mem::size_of::<RawInstruction>();

                        let mut patch = Patch {
                            address,
                            orig_insn: Instruction::new(*insn),
                            pattern: pattern.clone(),
                            applied: false,
                        };

                        if !ctx.check_coord.dispatcher.should_instruction_patched(
                            &patch,
                            hctx(ctx.child, ctx.check_coord, ctx.scope),
                        ) {
                            trace!(
                                "{} Instruction not interested @ {:#0x}: {:#0x}",
                                ctx.child,
                                address,
                                insn
                            );
                            continue;
                        }

                        patch.apply(&mut ctx.child.process_mut())?;
                        debug!(
                            "{} Instruction patched @ {:#0x}: {:#0x} -> {:#0x}",
                            ctx.child, address, insn, pattern.replace.value
                        );

                        ctx.check_coord.dispatcher.handle_instruction_patched(
                            &patch,
                            hctx(ctx.child, ctx.check_coord, ctx.scope),
                        )?;

                        patches_curr.insert(address, patch.clone());
                    }
                }
            }
        }

        Ok(())
    }

    fn handle_memory_map_removed(
        &self,
        map: &MemoryMap,
        ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        if self.patterns.is_empty() {
            return Ok(());
        }

        let mut patches_curr = self
            .patches
            .lock()
            .entry(ctx.child.role())
            .or_insert_with(|| Arc::new(Mutex::new(BTreeMap::new())))
            .clone()
            .lock_arc();

        if map == &MemoryMap::all() {
            patches_curr.clear();
        } else {
            let (removed, kept): (BTreeMap<usize, Patch>, BTreeMap<usize, Patch>) =
                std::mem::take(&mut *patches_curr)
                    .into_iter()
                    .partition(|(k, _)| *k >= map.start && *k < map.start + map.len);

            *patches_curr = kept;

            for (_, patch) in removed {
                ctx.check_coord
                    .dispatcher
                    .handle_instruction_patch_removed(
                        &patch,
                        hctx(ctx.child, ctx.check_coord, ctx.scope),
                    )?;
            }
        }

        Ok(())
    }

    fn handle_memory_map_updated(
        &self,
        _map: &MemoryMap,
        _ctx: HandlerContext<Stopped>,
    ) -> Result<()> {
        todo!()
    }
}

impl Module for InstructionPatcher {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_memory_event_handler(self);
    }
}
