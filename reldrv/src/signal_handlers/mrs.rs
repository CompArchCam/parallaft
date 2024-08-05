use std::{
    arch::asm,
    collections::HashMap,
    fmt::{Display, Formatter},
};

use log::{debug, info};
use nix::sys::signal::Signal;
use parking_lot::RwLock;

use crate::{
    dispatcher::{Module, Subscribers},
    error::{Error, Result, UnexpectedEventReason},
    events::{
        insn_patching::InstructionPatchingEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContext,
    },
    helpers::insn_patcher::{InstructionPatcher, Patch, PatchOwner, PatchPattern},
    process::{
        memory::instructions,
        registers::{Register, RegisterAccess},
        siginfo::SigInfoExt,
    },
    signal_handlers::handle_nondeterministic_instruction,
    types::segment_record::saved_trap_event::{SavedTrapEvent, SystemReg},
};

pub unsafe fn mrs(sys_reg: SystemReg) -> u64 {
    let value: u64;
    match sys_reg {
        SystemReg::MIDR_EL1 => {
            asm!("mrs {}, midr_el1", out(reg) value);
        }
        SystemReg::CTR_EL0 => {
            asm!("mrs {}, ctr_el0", out(reg) value);
        }
        SystemReg::DCZID_EL0 => {
            asm!("mrs {}, dczid_el0", out(reg) value);
        }
    }

    value
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub struct MrsInstruction {
    pub rt: Register,
    pub sys_reg: SystemReg,
}

impl Display for MrsInstruction {
    fn fmt(&self, f: &mut Formatter) -> std::fmt::Result {
        write!(f, "mrs {}, {:?}", self.rt, self.sys_reg)
    }
}

fn bitmask(start: u8, end: u8) -> u64 {
    ((1 << (end - start + 1)) - 1) << start
}

fn bitfield(value: u64, start: u8, end: u8) -> u64 {
    (value & bitmask(start, end)) >> start
}

pub struct MrsHandler {
    addresses: RwLock<HashMap<usize, MrsInstruction>>,
}

impl MrsHandler {
    pub fn new(patcher: &mut InstructionPatcher) -> Self {
        patcher.register_pattern(PatchPattern {
            mask: bitmask(20, 31) as _,
            search: 0xd5300000,
            replace: instructions::TRAP,
            owner: PatchOwner::Mrs,
        });

        Self {
            addresses: RwLock::new(HashMap::new()),
        }
    }
}

impl InstructionPatchingEventHandler for MrsHandler {
    fn should_instruction_patched(&self, patch: &Patch, _ctx: HandlerContext) -> bool {
        if patch.pattern.owner != PatchOwner::Mrs {
            return false;
        }

        let sys_reg = bitfield(patch.orig_insn.value as _, 5, 20);
        SystemReg::from_raw(sys_reg as _).is_some()
    }

    fn handle_instruction_patched(&self, patch: &Patch, ctx: HandlerContext) -> Result<()> {
        if patch.pattern.owner != PatchOwner::Mrs {
            return Ok(());
        }

        let sys_reg =
            SystemReg::from_raw(bitfield(patch.orig_insn.value as _, 5, 20) as _).unwrap();
        let rt = Register::from_raw(bitfield(patch.orig_insn.value as _, 0, 4) as _);

        let mrs_insn = MrsInstruction { rt, sys_reg };

        debug!(
            "{} MRS: Patched @ {:#0x}: {}",
            ctx.child, patch.address, mrs_insn
        );

        self.addresses.write().insert(patch.address, mrs_insn);
        Ok(())
    }

    fn handle_instruction_patch_removed(&self, patch: &Patch, _ctx: HandlerContext) -> Result<()> {
        if patch.pattern.owner != PatchOwner::Mrs {
            return Ok(());
        }

        debug!("MRS: Patch removed @ {:#0x}", patch.address);

        self.addresses.write().remove(&patch.address);
        Ok(())
    }
}

impl SignalHandler for MrsHandler {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: Signal,
        context: HandlerContext<'_, '_, 'disp, 'scope, 'env, '_, '_>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal != Signal::SIGTRAP || !context.child.process().get_siginfo()?.is_trap_bp() {
            return Ok(SignalHandlerExitAction::NextHandler);
        }

        let addresses = self.addresses.read();

        if let Some(mrs_insn) = addresses.get(&context.child.process().read_registers()?.ip() as _)
        {
            let mrs_result = handle_nondeterministic_instruction(
                &context.child,
                || unsafe { mrs(mrs_insn.sys_reg) },
                |value| SavedTrapEvent::Mrs(mrs_insn.rt, mrs_insn.sys_reg, value),
                |event| {
                    #[allow(irrefutable_let_patterns)]
                    if let SavedTrapEvent::Mrs(rt, sys_reg, value) = event {
                        if mrs_insn.rt != rt || mrs_insn.sys_reg != sys_reg {
                            return Err(Error::UnexpectedEvent(
                                UnexpectedEventReason::IncorrectTypeOrArguments,
                            ));
                        }

                        Ok(value)
                    } else {
                        Err(Error::UnexpectedEvent(
                            UnexpectedEventReason::IncorrectTypeOrArguments,
                        ))
                    }
                },
            )?;

            info!(
                "{} Trap: {} -> {:#0x}",
                context.child, mrs_insn, mrs_result.value
            );

            context.child.process_mut().modify_registers_with(|r| {
                r.set(mrs_insn.rt, mrs_result.value)
                    .with_instruction_skipped_unchecked(instructions::TRAP)
            })?;

            return Ok(mrs_result.signal_handler_exit_action());
        }

        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl Module for MrsHandler {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_instruction_patching_events_handler(self);
        subs.install_signal_handler(self);
    }
}
