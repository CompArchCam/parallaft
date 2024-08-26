pub mod begin_protection;
pub mod slice_segment;

use cfg_if::cfg_if;

use crate::error::Result;
use crate::process::state::Stopped;
use crate::types::process_id::InferiorRefMut;
use crate::types::segment_record::saved_trap_event::SavedTrapEvent;
use crate::types::segment_record::WithIsLastEvent;

cfg_if! {
    if #[cfg(target_arch = "x86_64")] {
        pub mod cpuid;
        pub mod rdtsc;
    }
    else if #[cfg(target_arch = "aarch64")] {
        pub mod mrs;
    }
}

pub fn handle_nondeterministic_instruction<R>(
    child: &InferiorRefMut<Stopped>,
    run_instr: impl FnOnce() -> R,
    create_event: impl FnOnce(R) -> SavedTrapEvent,
    replay_event: impl FnOnce(SavedTrapEvent) -> Result<R>,
) -> Result<WithIsLastEvent<R>>
where
    R: Copy,
{
    let ret;
    let mut is_last_event = false;
    match child {
        InferiorRefMut::Main(main) => {
            if let Some(segment) = &main.segment {
                // Main signal, inside protection zone
                ret = run_instr();
                #[allow(unreachable_code)]
                segment
                    .record
                    .push_event(create_event(ret), false, segment)?;
            } else {
                // Main signal, outside protection zone
                ret = run_instr();
            }
        }
        InferiorRefMut::Checker(checker) => {
            // Checker signal
            let result = checker.segment.record.pop_trap_event()?;
            is_last_event = result.is_last_event;

            ret = replay_event(*result.value)?;
        }
    };

    Ok(WithIsLastEvent::new(is_last_event, ret))
}
