use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Dispatcher, Installable},
    error::Result,
    process::Process,
    syscall_handlers::{
        HandlerContext, ProcessLifetimeHook, StandardSyscallHandler, SyscallHandlerExitAction,
    },
};

use super::{Statistics, Value};

pub struct TimingCollector {
    utime: AtomicU64,
    stime: AtomicU64,
    start_time: Mutex<Option<Instant>>,
    main_wall_time: Mutex<Option<Duration>>,
    all_wall_time: Mutex<Option<Duration>>,
}

impl TimingCollector {
    pub fn new() -> TimingCollector {
        TimingCollector {
            utime: AtomicU64::new(0),
            stime: AtomicU64::new(0),
            start_time: Mutex::new(None),
            main_wall_time: Mutex::new(None),
            all_wall_time: Mutex::new(None),
        }
    }

    pub fn main_wall_time(&self) -> Duration {
        self.main_wall_time.lock().unwrap_or_default()
    }
}

impl Statistics for TimingCollector {
    fn name(&self) -> &'static str {
        "timing"
    }

    fn statistics(&self) -> Box<[(&'static str, Value)]> {
        let ticks_per_second = procfs::ticks_per_second();
        let utime_ticks = self.utime.load(Ordering::SeqCst);
        let stime_ticks = self.stime.load(Ordering::SeqCst);

        let main_utime = utime_ticks as f64 / ticks_per_second as f64;
        let main_stime = stime_ticks as f64 / ticks_per_second as f64;
        let main_cpu_time = main_utime + main_stime;
        let main_wall_time = self.main_wall_time.lock().unwrap().as_secs_f64();
        let all_wall_time = self.all_wall_time.lock().unwrap().as_secs_f64();

        vec![
            ("main_user_time", Value::Float(main_utime)),
            ("main_sys_time", Value::Float(main_stime)),
            ("main_cpu_time", Value::Float(main_cpu_time)),
            ("main_wall_time", Value::Float(main_wall_time)),
            ("all_wall_time", Value::Float(all_wall_time)),
            (
                "main_cpu_usage",
                Value::Float(main_cpu_time / main_wall_time),
            ),
        ]
        .into_boxed_slice()
    }
}

impl StandardSyscallHandler for TimingCollector {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: &HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if context.process.pid == context.check_coord.main.pid {
            match syscall {
                Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                    let stats = context.process.stats()?;
                    self.utime.store(stats.utime, Ordering::SeqCst);
                    self.stime.store(stats.stime, Ordering::SeqCst);
                }
                _ => (),
            }
        }
        Ok(SyscallHandlerExitAction::NextHandler)
    }
}

impl ProcessLifetimeHook for TimingCollector {
    fn handle_main_init(&self, _process: &Process) {
        *self.start_time.lock() = Some(Instant::now())
    }

    fn handle_main_fini(&self, _ret_val: i32) {
        let elapsed = self.start_time.lock().unwrap().elapsed();
        *self.main_wall_time.lock() = Some(elapsed);
    }

    fn handle_all_fini(&self) {
        let elapsed = self.start_time.lock().unwrap().elapsed();
        *self.all_wall_time.lock() = Some(elapsed);
    }
}

impl<'a> Installable<'a> for TimingCollector {
    fn install(&'a self, dispatcher: &mut Dispatcher<'a>) {
        dispatcher.install_standard_syscall_handler(self);
        dispatcher.install_process_lifetime_hook(self);
    }
}
