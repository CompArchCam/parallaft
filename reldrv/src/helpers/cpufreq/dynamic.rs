use std::{
    collections::{BTreeMap, HashMap},
    sync::{
        mpsc::{channel, RecvTimeoutError, Sender},
        Arc,
    },
    time::{Duration, Instant},
};

use derivative::Derivative;
use itertools::Itertools;
use log::debug;
use nix::sys::signal::Signal;
use parking_lot::Mutex;
use perf_event::events::Hardware;
use try_insert_ext::OptionInsertExt;

use super::{cpuinfo::CpuInfo, utils::set_cpufreq_max_freq};
use crate::{
    dispatcher::Module,
    error::Result,
    events::{
        module_lifetime::ModuleLifetimeHook,
        process_lifetime::HandlerContext,
        segment::SegmentEventHandler,
        signal::{SignalHandler, SignalHandlerExitAction},
        HandlerContextWithInferior,
    },
    process::state::{Running, Stopped},
    types::{
        perf_counter::{
            symbolic_events::{expr::Target, GenericHardwareEventCounter},
            PerfCounter,
        },
        process_id::{Checker, InferiorRefMut, Main},
        segment::{Segment, SegmentId, SegmentStatus},
    },
};

pub struct DynamicCpuFreqScaler<'a> {
    checker_cpu_set: &'a [usize],
    checker_emerg_cpu_set: &'a [usize],
    segment_info_map: Mutex<BTreeMap<SegmentId, SegmentInfo>>,
    main_instruction_counter: Mutex<Option<GenericHardwareEventCounter>>,
    main_cycles_counter: Mutex<Option<GenericHardwareEventCounter>>,
    main_start_time: Mutex<Option<Instant>>,
    adjustment_period: Duration,
    worker: Mutex<Option<Sender<()>>>,
    state: Mutex<State>,
    cpu_info_map: Mutex<HashMap<usize, CpuInfo>>,
    freq_step_khz: u64,
    eps: f64,
    no_freq_change: bool,
}

#[derive(Derivative)]
#[derivative(Debug)]
struct SegmentInfo {
    segment: Arc<Segment>,
    main_instructions: u64,
    main_cycles: u64,
    main_start_time: Instant,
    main_end_time: Option<Instant>,
    #[derivative(Debug = "ignore")]
    checker_instruction_counter: Option<GenericHardwareEventCounter>,
    checker_instructions: u64,
    #[derivative(Debug = "ignore")]
    checker_cycle_counter: Option<GenericHardwareEventCounter>,
    checker_cycles: u64,
    checker_done: bool,
    checker_on_emerg: bool,
}

#[derive(Debug)]
struct State {
    last_main_instructions: HashMap<SegmentId, u64>,
    last_checker_instructions: HashMap<SegmentId, u64>,
    last_checker_cycles: HashMap<SegmentId, u64>,
    cur_freq_khz: f64,
}

impl State {
    fn new() -> State {
        State {
            last_main_instructions: HashMap::new(),
            last_checker_instructions: HashMap::new(),
            last_checker_cycles: HashMap::new(),
            cur_freq_khz: 3_000_000.0, /* TODO */
        }
    }
}

impl DynamicCpuFreqScaler<'_> {
    const SIGVAL_MIGRATE_CHECKER: usize = 0x787170ccb54c5460;

    pub fn new<'a>(
        checker_cpu_set: &'a [usize],
        checker_emerg_cpu_set: &'a [usize], // Big cores that can be used in case checkers cannot meet deadlines
        no_freq_change: bool,               // If true, the frequency will not be changed
    ) -> DynamicCpuFreqScaler<'a> {
        DynamicCpuFreqScaler {
            checker_cpu_set,
            checker_emerg_cpu_set,
            freq_step_khz: 50_000, /* 50MHz */
            segment_info_map: Mutex::new(BTreeMap::new()),
            main_instruction_counter: Mutex::new(None),
            main_cycles_counter: Mutex::new(None),
            adjustment_period: Duration::from_secs_f32(0.5),
            worker: Mutex::new(None),
            state: Mutex::new(State::new()),
            cpu_info_map: Mutex::new(HashMap::new()),
            main_start_time: Mutex::new(None),
            eps: 0.0,
            no_freq_change,
        }
    }

    // fn get_total_lag(segment_info_map: &HashMap<SegmentId, SegmentInfo>) -> u64 {
    //     segment_info_map.values().fold(0, |acc, segment_info| {
    //         acc + segment_info.main_instructions - segment_info.checker_instructions
    //     })
    // }

    fn update_counts(&self, segment_info: &mut SegmentInfo) -> Result<()> {
        if segment_info.main_end_time.is_none() {
            // Main is still running
            segment_info.main_instructions = self
                .main_instruction_counter
                .lock()
                .as_mut()
                .unwrap()
                .read()?;

            segment_info.main_cycles = self.main_cycles_counter.lock().as_mut().unwrap().read()?;
        }

        if let Some(counter) = &mut segment_info.checker_instruction_counter {
            segment_info.checker_instructions = counter.read()?;
        }

        if let Some(counter) = &mut segment_info.checker_cycle_counter {
            segment_info.checker_cycles = counter.read()?;
        }

        Ok(())
    }

    fn update_all_counts(
        &self,
        segment_info_map: &mut BTreeMap<SegmentId, SegmentInfo>,
    ) -> Result<()> {
        for segment_info in segment_info_map.values_mut() {
            self.update_counts(segment_info)?;
        }

        Ok(())
    }

    // fn calculate_diff(old: &HashMap<SegmentId, u64>, new: &HashMap<SegmentId, u64>) -> u64 {
    //     if let Some(segment_id_start) = new.keys().min() {
    //         let old_sum = old.iter().fold(0, |acc, (segment_id, v)| {
    //             if segment_id >= segment_id_start {
    //                 acc + v
    //             } else {
    //                 acc
    //             }
    //         });

    //         let new_sum: u64 = new.values().sum();

    //         new_sum - old_sum
    //     } else {
    //         0
    //     }
    // }

    fn set_freq(&self, freq: f64) -> Result<f64> {
        let cpu_info_map = self.cpu_info_map.lock();

        let freq_max = cpu_info_map.values().map(|x| x.freq_max_khz).max().unwrap();
        let freq_min = cpu_info_map.values().map(|x| x.freq_min_khz).min().unwrap();

        for cpu in self.checker_cpu_set {
            let cpu_info = cpu_info_map.get(cpu).unwrap();

            let freq_khz = (((freq / self.freq_step_khz as f64).ceil() * self.freq_step_khz as f64)
                as u64)
                .clamp(cpu_info.freq_min_khz, cpu_info.freq_max_khz);

            debug!("Setting CPU{cpu} max frequency to {freq_khz} KHz");

            set_cpufreq_max_freq(*cpu, freq_khz)?;
        }

        Ok(freq.clamp(freq_min as _, freq_max as _))
    }

    fn try_migrate(
        &self,
        segment_info: &mut SegmentInfo,
        nr_checkers_on_emerg: &mut usize,
    ) -> Result<bool> {
        if *nr_checkers_on_emerg >= self.checker_emerg_cpu_set.len() {
            debug!(
                "Segment {}: all big cores are busy, not migrating",
                segment_info.segment.nr
            );
            Ok(false)
        } else {
            debug!("Segment {}: migrating to big core", segment_info.segment.nr);

            segment_info
                .segment
                .checker_status
                .lock()
                .process()
                .unwrap()
                .sigqueue(Self::SIGVAL_MIGRATE_CHECKER)?;

            segment_info.checker_on_emerg = true;
            *nr_checkers_on_emerg += 1;
            Ok(true)
        }
    }

    fn do_adjustment(&self) -> Result<()> {
        let now = Instant::now();
        let mut state = self.state.lock();
        let mut segment_info_map = self.segment_info_map.lock();
        self.update_all_counts(&mut segment_info_map)?;

        let total_main_instructions = segment_info_map
            .iter()
            .map(|(k, v)| (*k, v.main_instructions))
            .collect::<HashMap<SegmentId, u64>>();

        let total_checker_instructions = segment_info_map
            .iter()
            .map(|(k, v)| (*k, v.checker_instructions))
            .collect::<HashMap<SegmentId, u64>>();

        let total_checker_cycles = segment_info_map
            .iter()
            .map(|(k, v)| (*k, v.checker_cycles))
            .collect::<HashMap<SegmentId, u64>>();

        let last_segment_id = segment_info_map.keys().max();
        let mut boosted = false;

        if let Some(last_segment_id) = last_segment_id {
            let segment_status = segment_info_map
                .get(last_segment_id)
                .unwrap()
                .segment
                .status
                .lock();

            if !self.no_freq_change
                && (!matches!(&*segment_status, SegmentStatus::Filling { .. })
                    || matches!(
                        &*segment_status,
                        SegmentStatus::Filling { blocked: true, .. }
                    ))
            {
                debug!("Boosting to max frequency because the main is waiting");
                state.cur_freq_khz = self.set_freq(f64::MAX)?;
                boosted = true;
            }
        }

        if !boosted {
            // let mut total_time_remaining = Duration::ZERO;
            // let mut total_instructions_remaining = 0;

            let mut nr_checkers_on_emerg = segment_info_map
                .values()
                .filter(|x| x.checker_on_emerg && !x.checker_done)
                .count();

            let mut max_needed_freq: f64 = 0.0;

            for segment_info in segment_info_map.values_mut() {
                if segment_info.checker_done || segment_info.checker_on_emerg {
                    continue;
                }

                let main_duration = segment_info
                    .main_end_time
                    .unwrap_or(now)
                    .duration_since(segment_info.main_start_time);

                let deadline = segment_info.main_start_time
                    + main_duration.mul_f64(self.checker_cpu_set.len() as f64 - self.eps);

                let time_remaining = deadline.duration_since(now);
                let instructions_remaining =
                    segment_info.main_instructions - segment_info.checker_instructions;

                if time_remaining > Duration::ZERO {
                    let delta_checker_cycles = segment_info.checker_cycles
                        - *state
                            .last_checker_cycles
                            .get(&segment_info.segment.nr)
                            .unwrap_or(&0);

                    let delta_checker_instructions = segment_info.checker_instructions
                        - *state
                            .last_checker_instructions
                            .get(&segment_info.segment.nr)
                            .unwrap_or(&0);

                    let checker_ipc =
                        delta_checker_instructions as f64 / delta_checker_cycles as f64;

                    debug!(
                        "Segment {}: checker IPC: {}",
                        segment_info.segment.nr, checker_ipc
                    );

                    if instructions_remaining < 1000000000 {
                        debug!(
                            "Segment {}: not enough instructions remaining",
                            segment_info.segment.nr
                        );
                        continue;
                    }

                    let needed_freq = instructions_remaining as f64
                        / checker_ipc
                        / time_remaining.as_secs_f64()
                        / 1000.0;

                    debug!(
                        "Segment {}: checker needed freq: {} kHz",
                        segment_info.segment.nr, needed_freq
                    );

                    if self.checker_emerg_cpu_set.len() > 0 {
                        let main_ipc =
                            segment_info.main_instructions as f64 / segment_info.main_cycles as f64;

                        debug!(
                            "Segment {}: main IPC: {}",
                            segment_info.segment.nr, main_ipc
                        );

                        let needed_freq_by_big_core = instructions_remaining as f64
                            / main_ipc
                            / time_remaining.as_secs_f64()
                            / 1000.0;

                        if needed_freq_by_big_core
                            > self
                                .cpu_info_map
                                .lock()
                                .get(&self.checker_emerg_cpu_set[0])
                                .unwrap()
                                .freq_max_khz as f64
                        {
                            if self.try_migrate(segment_info, &mut nr_checkers_on_emerg)? {
                                continue;
                            }
                        }
                    }

                    max_needed_freq = max_needed_freq.max(needed_freq);
                } else {
                    debug!("Missed deadlines, boosting frequency to max or migrating to big core");

                    if self.checker_emerg_cpu_set.len() > 0 {
                        if self.try_migrate(segment_info, &mut nr_checkers_on_emerg)? {
                            continue;
                        }
                    } else {
                        max_needed_freq = f64::MAX;
                    }
                }

                // TODO: this may be negative in the future
            }

            let nr_live_checkers = segment_info_map
                .values()
                .filter(|x| !x.checker_done && !x.segment.record.is_waiting())
                .count();

            debug!("Number of live checkers: {nr_live_checkers}");

            if !self.no_freq_change {
                state.cur_freq_khz = self.set_freq(max_needed_freq)?;
                debug!("Final checker freq: {} kHz", state.cur_freq_khz);
            }
        }

        state.last_main_instructions = total_main_instructions;
        state.last_checker_cycles = total_checker_cycles;
        state.last_checker_instructions = total_checker_instructions;

        Ok(())
    }
}

impl SegmentEventHandler for DynamicCpuFreqScaler<'_> {
    fn handle_checkpoint_created_post_fork(
        &self,
        main: &mut Main<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut instructions_counter_option = self.main_instruction_counter.lock();

        let instructions_counter = instructions_counter_option.get_or_try_insert_with(|| {
            GenericHardwareEventCounter::new(
                Hardware::INSTRUCTIONS,
                Target::Pid(main.process().pid),
                true,
                None,
            )
        })?;

        let instruction_count = instructions_counter.read()?;
        instructions_counter.reset()?;
        drop(instructions_counter_option);

        let mut cycles_counter_option = self.main_cycles_counter.lock();

        let cycles_counter = cycles_counter_option.get_or_try_insert_with(|| {
            GenericHardwareEventCounter::new(
                Hardware::CPU_CYCLES,
                Target::Pid(main.process().pid),
                true,
                None,
            )
        })?;

        let cycle_count = cycles_counter.read()?;
        cycles_counter.reset()?;
        drop(cycles_counter_option);

        *self.main_start_time.lock() = Some(Instant::now());

        if let Some(segment) = &main.segment {
            let mut map = self.segment_info_map.lock();
            let segment_info = map.get_mut(&segment.nr).unwrap();
            segment_info.main_instructions = instruction_count;
            segment_info.main_cycles = cycle_count;
            segment_info.main_end_time = Some(Instant::now());
        }

        Ok(())
    }

    fn handle_segment_created(&self, main: &mut Main<Running>) -> Result<()> {
        self.segment_info_map.lock().insert(
            main.segment.as_ref().unwrap().nr,
            SegmentInfo {
                segment: main.segment.as_ref().unwrap().clone(),
                main_instructions: 0,
                main_cycles: 0,
                main_start_time: self.main_start_time.lock().take().unwrap(),
                checker_instruction_counter: None,
                checker_instructions: 0,
                checker_cycle_counter: None,
                checker_cycles: 0,
                main_end_time: None,
                checker_done: false,
                checker_on_emerg: false,
            },
        );

        Ok(())
    }

    fn handle_segment_ready(
        &self,
        checker: &mut Checker<Stopped>,
        _ctx: HandlerContext,
    ) -> Result<()> {
        let mut segment_info_map = self.segment_info_map.lock();
        let segment_info = segment_info_map.get_mut(&checker.segment.nr).unwrap();

        segment_info.checker_instruction_counter = Some(GenericHardwareEventCounter::new(
            Hardware::INSTRUCTIONS,
            Target::Pid(checker.process().pid),
            true,
            None,
        )?);

        segment_info.checker_cycle_counter = Some(GenericHardwareEventCounter::new(
            Hardware::CPU_CYCLES,
            Target::Pid(checker.process().pid),
            true,
            None,
        )?);

        Ok(())
    }

    fn handle_segment_completed(&self, checker: &mut Checker<Stopped>) -> Result<()> {
        let mut segment_info_map = self.segment_info_map.lock();
        let segment_info = segment_info_map.get_mut(&checker.segment.nr).unwrap();

        self.update_counts(segment_info)?;

        segment_info.checker_instruction_counter = None;
        segment_info.checker_cycle_counter = None;
        segment_info.checker_done = true;

        Ok(())
    }

    fn handle_segment_removed(&self, segment: &Arc<Segment>) -> Result<()> {
        self.segment_info_map.lock().remove(&segment.nr);
        Ok(())
    }
}

impl ModuleLifetimeHook for DynamicCpuFreqScaler<'_> {
    fn init<'s, 'scope, 'env>(&'s self, ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        *self.cpu_info_map.lock() = self
            .checker_cpu_set
            .iter()
            .chain(self.checker_emerg_cpu_set.iter())
            .map(|x| CpuInfo::get(*x).map(|v| (*x, v)))
            .try_collect()?;

        let (tx, rx) = channel();
        *self.worker.lock() = Some(tx);

        std::thread::Builder::new()
            .name("dvfs-scaler".to_string())
            .spawn_scoped(ctx.scope, move || {
                while let Err(RecvTimeoutError::Timeout) = rx.recv_timeout(self.adjustment_period) {
                    self.do_adjustment().expect("Failed to adjust frequency");
                }
            })
            .unwrap();
        Ok(())
    }

    fn fini<'s, 'scope, 'env>(&'s self, _ctx: HandlerContext<'_, 'scope, '_, '_, '_>) -> Result<()>
    where
        's: 'scope,
    {
        let worker = self.worker.lock();

        if let Some(tx) = worker.as_ref() {
            tx.send(()).expect("Failed to stop worker");
        }

        Ok(())
    }
}

impl SignalHandler for DynamicCpuFreqScaler<'_> {
    fn handle_signal<'s, 'disp, 'scope, 'env>(
        &'s self,
        _signal: Signal,
        context: HandlerContextWithInferior<'_, '_, 'disp, 'scope, 'env, '_, '_, Stopped>,
    ) -> Result<SignalHandlerExitAction>
    where
        'disp: 'scope,
    {
        if let InferiorRefMut::Checker(checker) = context.child {
            if checker.process().get_sigval()? == Some(Self::SIGVAL_MIGRATE_CHECKER) {
                debug!("{checker} Migrating to emergency CPU set");

                context.check_coord.migrate_checker(
                    self.checker_emerg_cpu_set.into(),
                    checker,
                    context.scope,
                )?;

                return Ok(SignalHandlerExitAction::SuppressSignalAndContinueInferior {
                    single_step: false,
                });
            }
        }
        Ok(SignalHandlerExitAction::NextHandler)
    }
}

impl Module for DynamicCpuFreqScaler<'_> {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_segment_event_handler(self);
        subs.install_module_lifetime_hook(self);
        subs.install_signal_handler(self);
    }
}
