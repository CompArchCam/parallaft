use std::sync::atomic::{AtomicUsize, Ordering};

use log::info;
use parallaft::{
    check_coord::CheckCoordinatorOptions,
    dispatcher::Module,
    error::Result,
    events::{
        module_lifetime::ModuleLifetimeHook, process_lifetime::HandlerContext,
        syscall::CustomSyscallHandler, HandlerContextWithInferior,
    },
    process::state::Stopped,
    types::{perf_counter::cpu_info::pmu::PMUS, process_id::InferiorRefMut},
    RelShellOptionsBuilder,
};

use crate::common::{
    checkpoint_fini, checkpoint_take, custom_sysno::TestCustomSysno, migrate_checker,
    take_exec_point, trace_w_options,
};

struct MigrationHelper {
    cpusets: Vec<Vec<usize>>,
    pos: AtomicUsize,
}

/// Cycle though the cpusets. Move to the next cpuset when triggered by custom syscall MigrateChecker.
impl MigrationHelper {
    pub fn new(cpusets: Vec<Vec<usize>>) -> Self {
        Self {
            cpusets,
            pos: AtomicUsize::new(0),
        }
    }
}

impl CustomSyscallHandler for MigrationHelper {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<parallaft::events::syscall::SyscallHandlerExitAction> {
        match context.child {
            InferiorRefMut::Main(main) => {
                if TestCustomSysno::from_repr(sysno) == Some(TestCustomSysno::TakeExecPoint) {
                    context
                        .check_coord
                        .push_curr_exec_point_to_event_log(main, false)?;

                    info!("{} Took exec point", main);
                }
            }
            InferiorRefMut::Checker(checker) => {
                if TestCustomSysno::from_repr(sysno) == Some(TestCustomSysno::MigrateChecker) {
                    let pos = self.pos.fetch_add(1, Ordering::SeqCst);
                    let new_cpu_set = self.cpusets[pos % self.cpusets.len()].clone();

                    info!("{} Migrated checker to {:?}", checker, new_cpu_set);

                    context
                        .check_coord
                        .migrate_checker(new_cpu_set, *checker, context.scope)?;

                    return Ok(
                        parallaft::events::syscall::SyscallHandlerExitAction::ContinueInferior,
                    );
                }
            }
        }

        Ok(parallaft::events::syscall::SyscallHandlerExitAction::NextHandler)
    }
}

impl ModuleLifetimeHook for MigrationHelper {
    fn fini<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        assert_ne!(self.pos.load(std::sync::atomic::Ordering::SeqCst), 0);

        Ok(())
    }
}

impl Module for MigrationHelper {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut parallaft::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_custom_syscall_handler(self);
    }
}

#[test]
#[ignore = "requires heterogeneous pmc"]
fn test_pmc_migration() -> Result<()> {
    let cpusets: Vec<Vec<usize>> = PMUS.iter().map(|p| p.cpus.clone()).collect();

    assert!(cpusets.len() >= 2, "not enough pmus, needs 2+ pmus");

    trace_w_options::<()>(
        || {
            checkpoint_take();

            for i in 0..=(2_i32.pow(16)) {
                if i % 100 == 0 {
                    migrate_checker();
                }
                if i & (i - 1) == 0
                /* i is power of two */
                {
                    take_exec_point();
                }
            }
            checkpoint_fini();
            Ok(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .exec_point_replay(true)
            .main_cpu_set(vec![0])
            .checker_cpu_set(vec![0])
            .extra_modules(vec![Box::new(MigrationHelper::new(cpusets))])
            .check_coord_flags(CheckCoordinatorOptions {
                no_state_cmp: false,
                no_checker_exec: false,
                no_fork: false,
                ignore_miscmp: false,
                enable_async_events: true,
            })
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect();

    Ok(())
}
