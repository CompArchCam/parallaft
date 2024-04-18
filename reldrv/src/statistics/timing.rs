use std::{
    sync::atomic::{AtomicU64, Ordering},
    time::{Duration, Instant},
};

use parking_lot::Mutex;
use reverie_syscalls::Syscall;

use crate::{
    dispatcher::{Module, Subscribers},
    error::Result,
    events::{
        process_lifetime::{ProcessLifetimeHook, ProcessLifetimeHookContext},
        syscall::{StandardSyscallHandler, SyscallHandlerExitAction},
        HandlerContext,
    },
    statistics_list,
};

use super::{StatisticValue, StatisticsProvider};

pub struct TimingCollector {
    utime: AtomicU64,
    stime: AtomicU64,
    start_time: Mutex<Option<Instant>>,
    main_wall_time: Mutex<Option<Duration>>,
    all_wall_time: Mutex<Option<Duration>>,
    exit_status: Mutex<Option<i32>>,
}

impl Default for TimingCollector {
    fn default() -> Self {
        Self::new()
    }
}

impl TimingCollector {
    pub fn new() -> TimingCollector {
        TimingCollector {
            utime: AtomicU64::new(0),
            stime: AtomicU64::new(0),
            start_time: Mutex::new(None),
            main_wall_time: Mutex::new(None),
            all_wall_time: Mutex::new(None),
            exit_status: Mutex::new(None),
        }
    }

    pub fn main_wall_time(&self) -> Duration {
        self.main_wall_time.lock().unwrap_or_default()
    }
}

impl StatisticsProvider for TimingCollector {
    fn class_name(&self) -> &'static str {
        "timing"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn StatisticValue>)]> {
        let ticks_per_second = procfs::ticks_per_second();
        let utime_ticks = self.utime.load(Ordering::SeqCst);
        let stime_ticks = self.stime.load(Ordering::SeqCst);

        let main_utime = utime_ticks as f64 / ticks_per_second as f64;
        let main_stime = stime_ticks as f64 / ticks_per_second as f64;
        let main_cpu_time = main_utime + main_stime;
        let main_wall_time = self.main_wall_time.lock().unwrap().as_secs_f64();
        let all_wall_time = self.all_wall_time.lock().unwrap().as_secs_f64();
        let exit_status = self.exit_status.lock().unwrap_or(255);

        statistics_list!(
            main_user_time = main_utime,
            main_sys_time = main_stime,
            main_cpu_time = main_cpu_time,
            main_wall_time = main_wall_time,
            all_wall_time = all_wall_time,
            main_cpu_usage = main_cpu_time / main_wall_time,
            exit_status = exit_status
        )
    }
}

impl StandardSyscallHandler for TimingCollector {
    fn handle_standard_syscall_entry(
        &self,
        syscall: &Syscall,
        context: HandlerContext,
    ) -> Result<SyscallHandlerExitAction> {
        if context.child.is_main() {
            match syscall {
                Syscall::Exit(_) | Syscall::ExitGroup(_) => {
                    let stats = context.process().stats()?;
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
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        *self.start_time.lock() = Some(Instant::now());

        Ok(())
    }

    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        ret_val: i32,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        let elapsed = self.start_time.lock().unwrap().elapsed();
        *self.main_wall_time.lock() = Some(elapsed);
        *self.exit_status.lock() = Some(ret_val);

        Ok(())
    }

    fn handle_all_fini<'s, 'scope, 'disp>(
        &'s self,
        _context: ProcessLifetimeHookContext<'_, 'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'scope,
        's: 'disp,
        'disp: 'scope,
    {
        let elapsed = self.start_time.lock().unwrap().elapsed();
        *self.all_wall_time.lock() = Some(elapsed);

        Ok(())
    }
}

impl Module for TimingCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_standard_syscall_handler(self);
        subs.install_process_lifetime_hook(self);
        subs.install_stats_providers(self);
    }
}
