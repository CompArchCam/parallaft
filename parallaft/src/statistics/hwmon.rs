use std::{
    collections::HashMap,
    fmt::Display,
    panic::{catch_unwind, AssertUnwindSafe},
    sync::mpsc::Sender,
    time::{Duration, Instant},
};

use itertools::Itertools;
use libmedium::{
    hwmon::sync_hwmon::Hwmons,
    sensors::sync_sensors::{power::PowerSensor, SyncSensor},
};
use log::{debug, error};
use parking_lot::Mutex;
use serde::{Deserialize, Serialize};

use crate::{
    dispatcher::Module,
    error::{Error, Result},
    events::{module_lifetime::ModuleLifetimeHook, process_lifetime::HandlerContext},
};

use super::{StatisticValue, StatisticsProvider};

#[derive(Debug, Clone, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub struct HwmonSensorPath {
    hwmon: String,
    sensor: String,
}

impl HwmonSensorPath {
    pub fn parse(s: &str) -> Result<Self> {
        let (hwmon, sensor) = s.split_once("/").ok_or(Error::Other)?;

        Ok(Self {
            hwmon: hwmon.to_string(),
            sensor: sensor.to_string(),
        })
    }
}

impl Display for HwmonSensorPath {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        write!(f, "{}/{}", self.hwmon, self.sensor)
    }
}

#[derive(Debug)]
pub struct HwmonSensor {
    path: HwmonSensorPath,
    hwmon_id: u16,
    sensor_id: u16,
}

impl HwmonSensor {
    pub fn read_power(&self, hwmons: &Hwmons) -> f64 {
        hwmons
            .hwmon_by_index(self.hwmon_id)
            .unwrap()
            .power(self.sensor_id)
            .unwrap()
            .read_input()
            .unwrap()
            .as_watts()
    }
}

#[derive(Debug)]
struct State {
    last_sampled: Option<Instant>,
    readings: HashMap<HwmonSensorPath, f64>,
}

impl State {
    pub fn new() -> Self {
        Self {
            last_sampled: None,
            readings: HashMap::new(),
        }
    }
}

#[derive(Debug)]
pub struct HwmonCollector {
    interval: Duration,
    hwmons: Hwmons,
    sensors: Vec<HwmonSensor>,
    state: Mutex<State>,
    stop_tx: Mutex<Option<Sender<()>>>,
    worker_panicked: Mutex<bool>,
}

impl HwmonCollector {
    pub fn new(sample_interval: Duration, paths: Vec<HwmonSensorPath>) -> Self {
        let hwmons = libmedium::parse_hwmons().unwrap();

        for hwmon in hwmons.iter() {
            debug!("Hwmon: {}", hwmon.name());
            for (_, sensor) in hwmon.powers() {
                debug!("Hwmon: - Sensor: {}", sensor.name());
            }
        }

        let sensors = paths
            .into_iter()
            .map(|path| {
                let hwmon = hwmons
                    .hwmons_by_name(&path.hwmon)
                    .at_most_one()
                    .unwrap()
                    .unwrap();

                let sensor_id = *hwmon
                    .powers()
                    .iter()
                    .find(|(_, s)| s.name() == path.sensor)
                    .expect("Failed to find sensor")
                    .0;

                HwmonSensor {
                    path,
                    hwmon_id: hwmon.index(),
                    sensor_id,
                }
            })
            .collect_vec();

        Self {
            hwmons,
            sensors,
            state: Mutex::new(State::new()),
            interval: sample_interval,
            stop_tx: Mutex::new(None),
            worker_panicked: Mutex::new(false),
        }
    }

    pub fn sample(&self) {
        let now = Instant::now();
        let mut state = self.state.lock();
        let time_since_last_sampled = now - state.last_sampled.unwrap_or(now);

        for sensor in &self.sensors {
            let power = sensor.read_power(&self.hwmons);
            debug!("Hwmon: {}: {} W", sensor.path, power);

            *state.readings.entry(sensor.path.clone()).or_insert(0.0) +=
                time_since_last_sampled.as_secs_f64() * power;

            state.last_sampled = Some(now);
        }
    }
}

impl ModuleLifetimeHook for HwmonCollector {
    fn init<'s, 'scope, 'env>(
        &'s self,
        ctx: HandlerContext<'_, 'scope, '_, '_, '_>,
    ) -> crate::error::Result<()>
    where
        's: 'scope,
    {
        if self.sensors.is_empty() {
            return Ok(());
        }

        let (tx, rx) = std::sync::mpsc::channel();
        *self.stop_tx.lock() = Some(tx);

        debug!("Hwmon: Starting sampling thread");
        ctx.scope.spawn(move || {
            let result = catch_unwind(AssertUnwindSafe(|| loop {
                self.sample();
                if rx.recv_timeout(self.interval).is_ok() {
                    break;
                }
            }));

            if result.is_err() {
                error!("Hwmon: Sampling thread panicked");
                *self.worker_panicked.lock() = true;
                self.state.lock().readings.clear();
            }
        });

        Ok(())
    }

    fn fini<'s, 'scope, 'env>(
        &'s self,
        _ctx: HandlerContext<'_, 'scope, '_, '_, '_>,
    ) -> crate::error::Result<()>
    where
        's: 'scope,
    {
        if let Some(stop_tx) = self.stop_tx.lock().take() {
            stop_tx.send(()).ok();
        }

        Ok(())
    }
}

impl StatisticsProvider for HwmonCollector {
    fn class_name(&self) -> &'static str {
        "hwmon"
    }

    fn statistics(&self) -> Box<[(String, Box<dyn super::StatisticValue>)]> {
        let state = self.state.lock();
        state
            .readings
            .iter()
            .map(|(path, total_power)| {
                (path.to_string(), {
                    let t: Box<dyn StatisticValue> = Box::new(*total_power);
                    t
                })
            })
            .chain([("is_ok".to_owned(), {
                let t: Box<dyn StatisticValue> = Box::new(!*self.worker_panicked.lock());
                t
            })])
            .collect()
    }
}

impl Module for HwmonCollector {
    fn subscribe_all<'s, 'd>(&'s self, subs: &mut crate::dispatcher::Subscribers<'d>)
    where
        's: 'd,
    {
        subs.install_module_lifetime_hook(self);
        subs.install_stats_providers(self);
    }
}
