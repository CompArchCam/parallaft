use crate::{
    dispatcher::{Dispatcher, Installable},
    error::Result,
    process::Process,
    syscall_handlers::ProcessLifetimeHook,
};

pub struct AffinitySetter<'a> {
    main_cpu_set: &'a [usize],
    checker_cpu_set: &'a [usize],
}

impl<'a> AffinitySetter<'a> {
    pub fn new(main_cpu_set: &'a [usize], checker_cpu_set: &'a [usize]) -> Self {
        Self {
            main_cpu_set,
            checker_cpu_set,
        }
    }
}

impl<'a> ProcessLifetimeHook for AffinitySetter<'a> {
    fn handle_main_init(&self, process: &Process) -> Result<()> {
        process.set_cpu_affinity(self.main_cpu_set)?;

        Ok(())
    }

    fn handle_checker_init(&self, process: &Process) -> Result<()> {
        process.set_cpu_affinity(self.checker_cpu_set)?;

        Ok(())
    }
}

impl<'a, 'b> Installable<'b> for AffinitySetter<'a> {
    fn install(&'b self, dispatcher: &mut Dispatcher<'b>) {
        dispatcher.install_process_lifetime_hook(self);
    }
}
