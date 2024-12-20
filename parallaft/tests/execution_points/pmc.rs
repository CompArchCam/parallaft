use std::{arch::asm, sync::atomic::AtomicU64};

use log::info;
use parallaft::{
    dispatcher::Module,
    error::Result,
    events::{
        module_lifetime::ModuleLifetimeHook, process_lifetime::HandlerContext,
        syscall::CustomSyscallHandler, HandlerContextWithInferior,
    },
    exec_point_providers::{
        pmu::exec_point::BranchCounterBasedExecutionPoint, ExecutionPointProvider,
    },
    process::state::Stopped,
    RelShellOptionsBuilder,
};

use crate::common::{custom_sysno::TestCustomSysno, trace_w_options};

#[derive(Debug, Clone, Copy)]
enum TestMode {
    Constant(u64),
    Incrementing { initial: u64, step: u64 },
}

impl TestMode {
    pub fn initial(&self) -> u64 {
        match self {
            TestMode::Constant(initial) => *initial,
            TestMode::Incrementing { initial, .. } => *initial,
        }
    }
}

struct PmcTester {
    test_mode: TestMode,
    count_expected: AtomicU64,
}

impl PmcTester {
    pub fn new(test_mode: TestMode) -> Self {
        Self {
            test_mode,
            count_expected: AtomicU64::new(test_mode.initial()),
        }
    }
}

impl CustomSyscallHandler for PmcTester {
    fn handle_custom_syscall_entry(
        &self,
        sysno: usize,
        _args: syscalls::SyscallArgs,
        context: HandlerContextWithInferior<Stopped>,
    ) -> Result<parallaft::events::syscall::SyscallHandlerExitAction> {
        if TestCustomSysno::from_repr(sysno) == Some(TestCustomSysno::TestPmc) {
            if context.child.is_checker() {
                return Ok(parallaft::events::syscall::SyscallHandlerExitAction::ContinueInferior);
            }

            let exec_point = context
                .check_coord
                .dispatcher
                .get_current_execution_point(context.child)?;

            let branch_exec_point = exec_point
                .as_any()
                .downcast_ref::<BranchCounterBasedExecutionPoint>()
                .unwrap();

            info!("Current exec point: {:?}", exec_point);

            let count_expected;

            match self.test_mode {
                TestMode::Incrementing { step, .. } => {
                    count_expected = self
                        .count_expected
                        .fetch_add(step, std::sync::atomic::Ordering::SeqCst);
                }
                TestMode::Constant(_) => {
                    count_expected = self
                        .count_expected
                        .load(std::sync::atomic::Ordering::SeqCst);
                }
            }

            if count_expected != branch_exec_point.branch_count {
                panic!(
                    "Unexpected branch count {} != {}",
                    branch_exec_point.branch_count, count_expected
                );
            }

            return Ok(parallaft::events::syscall::SyscallHandlerExitAction::ContinueInferior);
        }

        Ok(parallaft::events::syscall::SyscallHandlerExitAction::NextHandler)
    }
}

impl ModuleLifetimeHook for PmcTester {
    fn fini<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        assert_ne!(
            self.count_expected
                .load(std::sync::atomic::Ordering::SeqCst),
            0
        );

        Ok(())
    }
}

impl Module for PmcTester {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut parallaft::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_custom_syscall_handler(self);
    }
}

#[test]
fn pmc_monotonicity() {
    trace_w_options::<()>(
        || {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                asm!(
                    "
                    mov rax, 0xff77 # checkpoint_take
                    syscall
                    mov rdx, 100
                2:
                    mov rax, {sysno_test_pmc:r}
                    syscall
                    dec rdx
                    jnz 2b
                
                    mov rax, 0xff78 # checkpoint_fini
                    syscall
                    ",
                    sysno_test_pmc = in(reg) TestCustomSysno::TestPmc as u32,
                    out("rdx") _,
                    out("rcx") _,
                    out("r11") _,
                    out("rax") _,
                )
            };

            #[cfg(target_arch = "aarch64")]
            unsafe {
                asm!(
                    "
                    mov w8, 0xff77 // checkpoint_take
                    svc #0
                    mov x9, 100
                2:
                    mov w8, {sysno_test_pmc:w}
                    svc #0
                    subs x9, x9, 1
                    cbnz x9, 2b

                    mov w8, 0xff78 // checkpoint_fini
                    svc #0
                    ",
                    sysno_test_pmc = in(reg) TestCustomSysno::TestPmc as u32,
                    out("w9") _,
                    out("w8") _,
                    out("x0") _,
                )
            }

            Ok(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .exec_point_replay(true)
            .main_cpu_set(vec![0])
            .checker_cpu_set(vec![0])
            .extra_modules(vec![Box::new(PmcTester::new(TestMode::Incrementing {
                initial: 0,
                step: 1,
            }))])
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}

#[test]
fn pmc_consistency() {
    trace_w_options::<()>(
        || {
            #[cfg(target_arch = "x86_64")]
            unsafe {
                asm!(
                    "
                    mov rax, 0xff77 # checkpoint_take
                    syscall
                    mov rdx, 100
                    jmp 2f
                2:
                    mov rax, {sysno_test_pmc:r}
                    syscall
                    mov rax, 0xff77 # checkpoint_take
                    syscall
                    dec rdx
                    jnz 2b
                
                    mov rax, 0xff78 # checkpoint_fini
                    syscall
                    ",
                    sysno_test_pmc = in(reg) TestCustomSysno::TestPmc as u32,
                    out("rdx") _,
                    out("rcx") _,
                    out("r11") _,
                    out("rax") _,
                )
            };

            #[cfg(target_arch = "aarch64")]
            unsafe {
                asm!(
                    "
                    mov w8, 0xff77 // checkpoint_take
                    svc #0
                    mov x9, 100
                    b 2f
                2:
                    mov w8, {sysno_test_pmc:w}
                    svc #0
                    mov w8, 0xff77 // checkpoint_take
                    svc #0
                    subs x9, x9, 1
                    cbnz x9, 2b

                    mov w8, 0xff78 // checkpoint_fini
                    svc #0
                    ",
                    sysno_test_pmc = in(reg) TestCustomSysno::TestPmc as u32,
                    out("w9") _,
                    out("w8") _,
                    out("x0") _,
                )
            }

            Ok(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .exec_point_replay(true)
            .main_cpu_set(vec![0])
            .checker_cpu_set(vec![0])
            .extra_modules(vec![Box::new(PmcTester::new(TestMode::Constant(1)))])
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}
