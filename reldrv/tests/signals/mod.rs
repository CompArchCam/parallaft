use std::{
    sync::mpsc::{channel, Sender},
    time::Duration,
};

use nix::sys::signal::Signal;
use parking_lot::Mutex;
use reldrv::{
    dispatcher::Module,
    events::{
        module_lifetime::ModuleLifetimeHook, process_lifetime::ProcessLifetimeHook,
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
        _main: &mut reldrv::types::process_id::Main<reldrv::process::state::Stopped>,
        context: reldrv::events::process_lifetime::HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> reldrv::error::Result<()>
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
                let checker_status = segment.checker_status.lock();
                if let Some(process) = checker_status.process() {
                    if process.kill_with_sig(Signal::SIGUSR2).is_ok() {
                        n += 1;
                    }
                }
            }

            if context
                .check_coord
                .main
                .kill_with_sig(Signal::SIGUSR2)
                .is_ok()
            {
                n += 1;
            }

            println!("Injected SIGUSR2 to {} processes", n);
        });

        *self.stop_tx.lock() = Some(tx);

        Ok(())
    }
}

impl ModuleLifetimeHook for SignalInjector {
    fn fini<'s, 'scope, 'env>(
        &'s self,
        _scope: &'scope std::thread::Scope<'scope, 'env>,
    ) -> reldrv::error::Result<()>
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
        _context: reldrv::events::HandlerContextWithInferior<
            '_,
            '_,
            'disp,
            'scope,
            'env,
            '_,
            '_,
            reldrv::process::state::Stopped,
        >,
    ) -> reldrv::error::Result<reldrv::events::signal::SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if signal == Signal::SIGUSR2 {
            Ok(reldrv::events::signal::SignalHandlerExitAction::SuppressSignalAndContinueInferior { single_step: false })
        } else {
            Ok(reldrv::events::signal::SignalHandlerExitAction::NextHandler)
        }
    }
}

impl Module for SignalInjector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut reldrv::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
        subs.install_signal_handler(self);
        subs.install_module_lifetime_hook(self);
    }
}

#[test]
fn test_signal_handling() {
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
    .expect()
}
