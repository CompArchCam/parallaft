use std::{collections::BTreeMap, num::NonZeroUsize, os::fd::OwnedFd, ptr::write_bytes, sync::Arc};

use itertools::Itertools;
use nix::{
    sched::{sched_setaffinity, CpuSet},
    sys::mman::{self, munmap},
    unistd::Pid,
};
use parking_lot::Mutex;
use perf_event::events::Hardware;
use parallaft::{
    check_coord::CheckCoordinatorOptions,
    dispatcher::Module,
    error::Result,
    events::process_lifetime::{HandlerContext, ProcessLifetimeHook},
    process::{state::Stopped, PAGESIZE},
    types::{
        exit_reason::ExitReason,
        perf_counter::{
            symbolic_events::{expr::Target, GenericHardwareEventCounter},
            PerfCounter,
        },
        process_id::Main,
    },
    RelShellOptionsBuilder,
};

use crate::common::{checkpoint_fini, checkpoint_take, trace_w_options};

struct CyclesCounter {
    cpu_affinity: usize,
    events: Mutex<BTreeMap<String, GenericHardwareEventCounter>>,
    values: Arc<Mutex<BTreeMap<String, u64>>>,
}

impl CyclesCounter {
    pub const EVENT_LIST: [(&'static str, Hardware); 2] = [
        ("cycles", Hardware::CPU_CYCLES),
        ("ref_cycles", Hardware::REF_CPU_CYCLES),
    ];

    pub fn new(cpu_affinity: usize, values: Arc<Mutex<BTreeMap<String, u64>>>) -> Self {
        Self {
            cpu_affinity,
            events: Mutex::new(BTreeMap::new()),
            values,
        }
    }
}

impl ProcessLifetimeHook for CyclesCounter {
    fn handle_main_init<'s, 'scope, 'disp>(
        &'s self,
        _main: &mut Main<Stopped>,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        let mut counters = self.events.lock();

        for (name, event) in Self::EVENT_LIST {
            counters.insert(
                name.to_string(),
                GenericHardwareEventCounter::new(
                    event,
                    Target::Cpu(self.cpu_affinity),
                    false,
                    Some(&[self.cpu_affinity]),
                )?,
            );
        }

        Ok(())
    }

    fn handle_main_fini<'s, 'scope, 'disp>(
        &'s self,
        _main: &mut Main<Stopped>,
        _exit_reason: &ExitReason,
        _context: HandlerContext<'disp, 'scope, '_, '_, '_>,
    ) -> Result<()>
    where
        's: 'disp,
        'disp: 'scope,
    {
        let mut values = self.values.lock();
        for (name, counter) in &mut *self.events.lock() {
            values.insert(name.clone(), counter.read()?);
        }

        Ok(())
    }
}

impl Module for CyclesCounter {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut parallaft::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_process_lifetime_hook(self);
    }
}

fn run_bench(
    alloc_pages: usize,
    writing_pages: usize,
    num_iter: usize,
    cpu_affinity: usize,
    do_checkpoints: bool,
) -> BTreeMap<String, u64> {
    let page_size = *PAGESIZE;

    let values = Arc::new(Mutex::new(BTreeMap::new()));

    trace_w_options(
        || -> Result<()> {
            let mut cpuset = CpuSet::new();
            cpuset.set(cpu_affinity).unwrap();

            sched_setaffinity(Pid::from_raw(0), &cpuset)?;

            let buf = unsafe {
                mman::mmap::<OwnedFd>(
                    None,
                    NonZeroUsize::new(alloc_pages * page_size).unwrap(),
                    mman::ProtFlags::PROT_READ | mman::ProtFlags::PROT_WRITE,
                    mman::MapFlags::MAP_ANONYMOUS | mman::MapFlags::MAP_PRIVATE,
                    None,
                    0,
                )?
            } as *mut u8;

            unsafe { write_bytes(buf, 1, alloc_pages * page_size) };

            for _ in 0..num_iter {
                if do_checkpoints {
                    checkpoint_take();
                }
                unsafe { write_bytes(buf, 2, writing_pages * page_size) };
            }

            if do_checkpoints {
                checkpoint_fini();
            }

            unsafe { munmap(buf as *mut _, alloc_pages * page_size)? };

            Ok(())
        },
        RelShellOptionsBuilder::test_parallel_default()
            .extra_modules(vec![Box::new(CyclesCounter::new(
                cpu_affinity,
                values.clone(),
            ))])
            .main_cpu_set(vec![cpu_affinity])
            .check_coord_flags(CheckCoordinatorOptions {
                no_state_cmp: false,
                no_checker_exec: true,
                no_fork: false,
                ignore_miscmp: false,
                enable_async_events: false,
            })
            .build()
            .unwrap(),
    )
    .unwrap()
    .expect();

    let values = values.lock();
    values.clone()
}

#[ignore = "benchmark use only"]
#[test]
fn run_checkpoint_bench_set() {
    let cpu_affinity: usize = std::env::var("RELSH_TEST_CPU_AFFINITY")
        .unwrap_or("0".to_string())
        .parse()
        .unwrap();

    println!("Test: assuming CPU {cpu_affinity} is isolated");

    const ALLOC_PAGES: usize = 1024 * 1024 /* 4GB */;
    const WRITING_PAGES_LIST: [usize; 4] = [
        0,
        256 * 1024,  /* 1GB */
        512 * 1024,  /* 2GB */
        1024 * 1024, /* 4GB */
    ];

    const NUM_ITER: usize = 10;

    println!(
        "do_checkpoints,writing_pages,{}",
        CyclesCounter::EVENT_LIST.map(|x| x.0).join(",")
    );

    for writing_pages in WRITING_PAGES_LIST {
        let cycles = run_bench(ALLOC_PAGES, writing_pages, NUM_ITER, cpu_affinity, true);
        println!("1,{writing_pages},{}", cycles.values().join(","));

        let cycles = run_bench(ALLOC_PAGES, writing_pages, NUM_ITER, cpu_affinity, false);
        println!("0,{writing_pages},{}", cycles.values().join(","));
    }
}
