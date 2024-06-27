use std::path::Path;

use lazy_static::lazy_static;
use nix::{sys::signal::Signal, unistd::Pid};
use perf_event::{
    events::{Breakpoint, Event, Hardware, Raw},
    SampleSkid,
};

use crate::{
    error::{Error, Result},
    process::Process,
};

use super::{
    pmu_type::PmuType, sub::SubPerfCounter, BranchCounterType, PerfCounter,
    PerfCounterCheckInterrupt, PerfCounterWithInterrupt,
};

lazy_static! {
    static ref INTEL_CORE_ATOM_TY: Result<u32> = {
        let path = Path::new("/sys/bus/event_source/devices/cpu_atom/type");
        Ok(std::fs::read_to_string(path)?.trim().parse()?)
    };
}

struct RawWithDeviceType {
    ty: u32,
    config: u64,
}

impl RawWithDeviceType {
    pub fn new(ty: u32, config: u64) -> Self {
        Self { ty, config }
    }
}

impl Event for RawWithDeviceType {
    fn update_attrs(self, attr: &mut perf_event_open_sys::bindings::perf_event_attr) {
        attr.type_ = self.ty;
        attr.config = self.config;
        attr.__bindgen_anon_3.config1 = 0;
        attr.__bindgen_anon_4.config2 = 0;
    }
}

struct HardwareWithDeviceType {
    ty: u32,
    config: Hardware,
}

impl HardwareWithDeviceType {
    pub fn new(ty: u32, config: Hardware) -> Self {
        Self { ty, config }
    }
}

impl Event for HardwareWithDeviceType {
    fn update_attrs(self, attr: &mut perf_event_open_sys::bindings::perf_event_attr) {
        attr.type_ = perf_event_open_sys::bindings::PERF_TYPE_HARDWARE;
        attr.config = <Hardware as Into<u64>>::into(self.config) | ((self.ty as u64) << 32);
    }
}

pub struct LinuxPerfCounter(perf_event::Counter);

mod constants {
    pub const AMD_EX_RET_BRN: u64 = 0xc2;
    pub const AMD_EX_RET_BRN_FAR: u64 = 0xc6;
    pub const INTEL_BR_INST_RETIRED_ALL_BRANCHES: u64 = 0x00c4;
    pub const INTEL_LAKE_COVE_BR_INST_RETIRED_FAR_BRANCH: u64 = 0x40c4;
    pub const INTEL_MONT_BR_INST_RETIRED_FAR_BRANCH: u64 = 0xbfc4;
    pub const INTEL_LAKE_COVE_BR_INST_RETIRED_COND: u64 = 0x11c4;
    pub const INTEL_MONT_BR_INST_RETIRED_COND: u64 = 0x7ec4;
    pub const INTEL_LAKE_COVE_BR_INST_RETIRED_COND_TAKEN: u64 = 0x01c4;
    pub const INTEL_MONT_BR_INST_RETIRED_COND_TAKEN: u64 = 0xfec4;
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Target {
    Pid(Pid),
    Cpu(usize),
}

impl LinuxPerfCounter {
    pub fn new<E>(
        event: E,
        target: Target,
        pinned: bool,
        irq_cfg: Option<(u64, perf_event::SampleSkid)>,
    ) -> std::io::Result<Self>
    where
        E: Event,
    {
        let mut builder = perf_event::Builder::new(event);
        let mut counter = builder.pinned(pinned).enabled(true);

        counter = match target {
            Target::Pid(pid) => counter.observe_pid(pid.as_raw() as _),
            Target::Cpu(cpu) => counter.any_pid().include_kernel().include_hv().one_cpu(cpu),
        };

        if let Some((irq_period, sample_skid)) = irq_cfg {
            counter = counter
                .wakeup_events(1)
                .sample_period(irq_period)
                .sigtrap(true)
                .precise_ip(sample_skid)
                .remove_on_exec(true);
        }

        Ok(Self(counter.build()?))
    }

    pub fn interrupt_after_n_hw_events(
        event: Hardware,
        pmu_type: PmuType,
        target: Target,
        n: u64,
    ) -> Result<Self> {
        Ok(match pmu_type {
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelMont { in_hybrid: true } => Self::new(
                HardwareWithDeviceType::new((&*INTEL_CORE_ATOM_TY).clone()?, event),
                target,
                true,
                Some((n, SampleSkid::Arbitrary)),
            )?,
            _ => Self::new(event, target, true, Some((n, SampleSkid::Arbitrary)))?,
        })
    }

    pub fn count_hw_events(
        event: Hardware,
        pmu_type: PmuType,
        pinned: bool,
        target: Target,
    ) -> Result<Self> {
        Ok(match pmu_type {
            #[cfg(target_arch = "x86_64")]
            PmuType::IntelMont { in_hybrid: true } => Self::new(
                HardwareWithDeviceType::new((&*INTEL_CORE_ATOM_TY).clone()?, event),
                target,
                pinned,
                None,
            )?,
            _ => Self::new(event, target, pinned, None)?,
        })
    }

    pub fn interrupt_on_breakpoint(target: Target, ip: usize) -> Result<Self> {
        Ok(Self::new(
            Breakpoint::execute(ip as _),
            target,
            true,
            Some((1, SampleSkid::Arbitrary)),
        )?)
    }

    pub fn count_branches_with_interrupt(
        pmu_type: PmuType,
        branch_counter_type: BranchCounterType,
        target: Target,
        irq_period: Option<u64>,
    ) -> Result<Box<dyn PerfCounterWithInterrupt + Send>> {
        Ok(match (pmu_type, branch_counter_type) {
            #[cfg(target_arch = "x86_64")]
            (PmuType::Amd, BranchCounterType::AllExclFar) => Box::new(SubPerfCounter(
                Self::new(
                    Raw::new(constants::AMD_EX_RET_BRN),
                    target,
                    true,
                    irq_period.map(|period| (period, SampleSkid::Arbitrary)),
                )?,
                Self::new(Raw::new(constants::AMD_EX_RET_BRN_FAR), target, true, None)?,
            )),
            #[cfg(target_arch = "x86_64")]
            (PmuType::IntelLakeCove, BranchCounterType::AllExclFar)
            | (PmuType::IntelOther, BranchCounterType::AllExclFar) => Box::new(SubPerfCounter(
                Self::new(
                    Raw::new(constants::INTEL_BR_INST_RETIRED_ALL_BRANCHES),
                    target,
                    true,
                    irq_period.map(|period| (period, SampleSkid::RequireZero)),
                )?,
                Self::new(
                    Raw::new(constants::INTEL_LAKE_COVE_BR_INST_RETIRED_FAR_BRANCH),
                    target,
                    true,
                    None,
                )?,
            )),
            #[cfg(target_arch = "x86_64")]
            (PmuType::IntelMont { in_hybrid }, BranchCounterType::AllExclFar) => {
                let perf_event_type = if in_hybrid {
                    (&*INTEL_CORE_ATOM_TY).clone()? /* cpu_atom */
                } else {
                    0x04 /* cpu */
                };

                Box::new(SubPerfCounter(
                    Self::new(
                        RawWithDeviceType::new(
                            perf_event_type,
                            constants::INTEL_BR_INST_RETIRED_ALL_BRANCHES,
                        ),
                        target,
                        true,
                        irq_period.map(|period| (period, SampleSkid::RequireZero)),
                    )?,
                    Self::new(
                        RawWithDeviceType::new(
                            perf_event_type,
                            constants::INTEL_MONT_BR_INST_RETIRED_FAR_BRANCH,
                        ),
                        target,
                        true,
                        None,
                    )?,
                ))
            }
            #[cfg(target_arch = "x86_64")]
            (PmuType::IntelLakeCove, BranchCounterType::Cond)
            | (PmuType::IntelOther, BranchCounterType::Cond) => Box::new(Self::new(
                Raw::new(constants::INTEL_LAKE_COVE_BR_INST_RETIRED_COND),
                target,
                true,
                irq_period.map(|period| (period, SampleSkid::RequireZero)),
            )?),
            #[cfg(target_arch = "x86_64")]
            (PmuType::IntelMont { in_hybrid }, BranchCounterType::Cond) => {
                let perf_event_type = if in_hybrid {
                    (&*INTEL_CORE_ATOM_TY).clone()? /* cpu_atom */
                } else {
                    0x04 /* cpu */
                };

                Box::new(Self::new(
                    RawWithDeviceType::new(
                        perf_event_type,
                        constants::INTEL_MONT_BR_INST_RETIRED_COND,
                    ),
                    target,
                    true,
                    irq_period.map(|period| (period, SampleSkid::RequireZero)),
                )?)
            }
            #[cfg(target_arch = "x86_64")]
            (PmuType::IntelLakeCove, BranchCounterType::CondTaken)
            | (PmuType::IntelOther, BranchCounterType::CondTaken) => Box::new(Self::new(
                Raw::new(constants::INTEL_LAKE_COVE_BR_INST_RETIRED_COND_TAKEN),
                target,
                true,
                irq_period.map(|period| (period, SampleSkid::RequireZero)),
            )?),
            #[cfg(target_arch = "x86_64")]
            (PmuType::IntelMont { in_hybrid }, BranchCounterType::CondTaken) => {
                let perf_event_type = if in_hybrid {
                    (&*INTEL_CORE_ATOM_TY).clone()? /* cpu_atom */
                } else {
                    0x04 /* cpu */
                };

                Box::new(Self::new(
                    RawWithDeviceType::new(
                        perf_event_type,
                        constants::INTEL_MONT_BR_INST_RETIRED_COND_TAKEN,
                    ),
                    target,
                    true,
                    irq_period.map(|period| (period, SampleSkid::RequireZero)),
                )?)
            }
            _ => Err(Error::NotSupported(
                "Unsupported PMU and branch type combination".to_string(),
            ))?,
        })
    }
}

impl PerfCounter for LinuxPerfCounter {
    fn enable(&mut self) -> std::io::Result<()> {
        self.0.enable()
    }

    fn disable(&mut self) -> std::io::Result<()> {
        self.0.disable()
    }

    fn reset(&mut self) -> std::io::Result<()> {
        self.0.reset()
    }

    fn read(&mut self) -> std::io::Result<u64> {
        self.0.read()
    }
}

impl PerfCounterCheckInterrupt for LinuxPerfCounter {
    fn is_interrupt(&self, signal: Signal, process: &Process) -> Result<bool> {
        Ok(
            signal == Signal::SIGTRAP && process.get_siginfo()?.si_code == 0x6, /* TRAP_PERF */
        )
    }
}

impl PerfCounterWithInterrupt for LinuxPerfCounter {}
