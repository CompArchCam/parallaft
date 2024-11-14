use log::{debug, error};
use syscalls::SyscallArgs;

use crate::{
    dispatcher::Module,
    error::{Error, Result, UnexpectedEventReason},
    events::{
        syscall::{CustomSyscallHandler, SyscallHandlerExitAction},
        HandlerContextWithInferior,
    },
    exec_point_providers::ExecutionPointProvider,
    process::state::Stopped,
    types::{
        custom_sysno::CustomSysno,
        process_id::{InferiorRefMut, Main},
        segment_record::exec_point_sync_check::ExecutionPointSyncCheck,
    },
};

pub struct ExecutionPointSyncChecker;

impl CustomSyscallHandler for ExecutionPointSyncChecker {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: SyscallArgs,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<SyscallHandlerExitAction> {
        if CustomSysno::from_repr(sysno) == Some(CustomSysno::CheckExecPointSync) {
            match context.child {
                InferiorRefMut::Main(Main {
                    segment: Some(segment),
                    ..
                }) => {
                    let segment = segment.clone();

                    let exec_point = context
                        .check_coord
                        .dispatcher
                        .get_current_execution_point(context.child)?;

                    segment
                        .record
                        .push_event(ExecutionPointSyncCheck(exec_point), false)?;
                }
                InferiorRefMut::Checker(checker) => {
                    let exec_point = context
                        .check_coord
                        .dispatcher
                        .get_current_execution_point(&mut (*checker).into())?;

                    let exec_point_expected = checker
                        .exec
                        .clone()
                        .replay
                        .pop_execution_point_sync_check(checker)?
                        .value;

                    if exec_point.as_ref() != exec_point_expected.0.as_ref() {
                        error!(
                            "{checker} Execution point mismatch: {} != {}",
                            exec_point, exec_point_expected.0
                        );

                        return Err(Error::UnexpectedEvent(
                            UnexpectedEventReason::IncorrectValue,
                        ));
                    } else {
                        debug!("{checker} Execution point matched: {}", exec_point);
                    }
                }
                _ => {
                    debug!(
                        "{} Outside protection zones, ignoring execution point sync check",
                        context.child
                    );
                }
            }

            return Ok(SyscallHandlerExitAction::ContinueInferior);
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl Module for ExecutionPointSyncChecker {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_custom_syscall_handler(self);
    }
}
