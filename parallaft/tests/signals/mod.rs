use std::{
    sync::mpsc::{channel, Sender},
    time::Duration,
};

use log::info;
use nix::{
    libc,
    sys::signal::{raise, sigaction, SaFlags, SigAction, SigHandler, SigSet, Signal},
};
use parking_lot::Mutex;
use parallaft::{
    dispatcher::Module,
    events::{
        module_lifetime::ModuleLifetimeHook,
        process_lifetime::{HandlerContext, ProcessLifetimeHook},
        signal::SignalHandler,
    },
    RelShellOptionsBuilder,
};

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

struct SignalInjector {
    stop_tx: Mutex<Option<Sender<()>>>,
}

impl SignalInjector {
    pub fn new() -> Self {
        Self {
            stop_tx: Mutex::new(None),
        }
    }
}

impl ProcessLifetimeHook for SignalInjector {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        _main: &mut parallaft::types::process_id::Main<parallaft::process::state::Stopped>,
        context: parallaft::events::process_lifetime::HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> parallaft::error::Result<()>
    where
        's: 'disp + 'scope,
    {
        let (tx, rx) = channel();

        context.scope.spawn(move || loop {
            if rx.recv_timeout(Duration::from_millis(10)).is_ok() {
                break;
            }

            let mut n = 0;

            let segments = context.check_coord.segments.read();

            for segment in segments.list.iter() {
                let checker_status = segment.main_checker_exec.status.lock();
                if let Some(process) = checker_status.process() {
                    if process.kill_with_sig(Signal::SIGUSR1).is_ok() {
                        n += 1;
                    }
                }
            }

            if context
                .check_coord
                .main
                .kill_with_sig(Signal::SIGUSR1)
                .is_ok()
            {
                n += 1;
            }

            info!("Injected SIGUSR1 to {} processes", n);
        });

        *self.stop_tx.lock() = Some(tx);

        Ok(())
    }
}

impl ModuleLifetimeHook for SignalInjector {
    fn fini<'s, 'scope, 'env>(
        &'s self,
        _ctx: HandlerContext<'_, 'scope, '_, '_, '_>,
    ) -> parallaft::error::Result<()>
    where
        's: 'scope,
    {
        self.stop_tx.lock().take().unwrap().send(()).unwrap();
        Ok(())
    }
}

impl SignalHandler for SignalInjector {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        signal: nix::sys::signal::Signal,
        context: parallaft::events::HandlerContextWithInferior<
            '_,
            '_,
            'disp,
            'scope,
            'env,
            '_,
            '_,
            parallaft::process::state::Stopped,
        >,
    ) -> parallaft::error::Result<parallaft::events::signal::SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGUSR1 {
            info!("{} Received SIGUSR1", context.child);
            Ok(parallaft::events::signal::SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step: false })
        } else {
            Ok(parallaft::events::signal::SignalHandlerExitAction::NextHandler)
        }
    }
}

impl Module for SignalInjector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut parallaft::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_signal_handler(self);
        subs.install_module_lifetime_hook(self);
    }
}

#[test]
fn test_module_signal_handling() {
    trace_w_options(
        || {
            for _ in 0..2000 {
                checkpoint_take();
            }
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .extra_modules(vec![Box::new(SignalInjector::new())])
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}

#[test]
fn test_external_signal_handling() {
    extern "C" fn handler(
        signum: i32,
        siginfo: *mut libc::siginfo_t,
        _ucontext: *mut libc::c_void,
    ) {
        println!("{}", signum);
        println!("{:?}", unsafe { &*siginfo }); // Make sure the checker gets the same siginfo_t
    }

    trace_w_options(
        || {
            unsafe {
                sigaction(
                    Signal::SIGUSR2,
                    &SigAction::new(
                        SigHandler::SigAction(handler),
                        SaFlags::SA_SIGINFO,
                        SigSet::empty(),
                    ),
                )
                .unwrap();
            }
            checkpoint_take();
            raise(Signal::SIGUSR2).unwrap();
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .test_with_exec_point_replay()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect()
}

#[test]
fn test_internal_signal_handling() {
    trace_w_options(
        || {
            unsafe {
                sigaction(
                    Signal::SIGSEGV,
                    &SigAction::new(SigHandler::SigDfl, SaFlags::SA_SIGINFO, SigSet::empty()),
                )
                .unwrap();
            }

            checkpoint_take();
            #[allow(deref_nullptr)]
            unsafe {
                *(0 as *mut i32) = 1 // cause a SIGSEGV
            };
            checkpoint_fini();
            Ok::<_, ()>(())
        },
        RelShellOptionsBuilder::test_serial_default()
            .test_with_exec_point_replay()
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect_signalled(Signal::SIGSEGV);
}
