#[cfg(target_arch = "x86_64")]
pub mod cpuid;

#[cfg(target_arch = "x86_64")]
pub mod rdtsc;


use crate::check_coord::{CheckCoordinator, ProcessIdentityRef, UpgradableReadGuard};
use crate::error::{Error, Result, UnexpectedEventReason};
use crate::types::segment::Segment;
use crate::types::segment_record::saved_trap_event::SavedTrapEvent;

pub fn handle_nondeterministic_instruction<R>(
    child: &mut ProcessIdentityRef<'_, UpgradableReadGuard<Segment>>,
    check_coord: &CheckCoordinator,
    run_instr: impl FnOnce() -> R,
    create_event: impl FnOnce(R) -> SavedTrapEvent,
    replay_event: impl FnOnce(SavedTrapEvent) -> Result<R>,
) -> Result<R>
where
    R: Copy,
{
    let ret;
    match child {
        ProcessIdentityRef::Main(_) => {
            let segments = check_coord.segments.read();
            if let Some(segment) = segments.main_segment() {
                let mut segment = segment.write_arc();
                // Main signal, inside protection zone
                drop(segments);
                ret = run_instr();
                segment.record.push_trap_event(create_event(ret));
            } else {
                // Main signal, outside protection zone
                ret = run_instr();
            }
        }
        ProcessIdentityRef::Checker(segment) => {
            // Checker signal
            let event = segment.with_upgraded(|segment| {
                let r = segment
                    .record
                    .next_trap_event()
                    .ok_or(Error::UnexpectedTrap(UnexpectedEventReason::Excess))?;

                Ok::<_, Error>(*r)
            })?;

            ret = replay_event(event)?;
        }
    };

    Ok(ret)
}
