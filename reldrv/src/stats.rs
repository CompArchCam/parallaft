use parking_lot::Mutex;

struct RunningAverage {
    data: Mutex<(f64, usize)>,
}

impl RunningAverage {
    pub fn new() -> Self {
        Self {
            data: Mutex::new((0.0, 0)),
        }
    }
    pub fn get(&self) -> f64 {
        self.data.lock().0
    }

    pub fn update(&self, value: f64) {
        let mut data = self.data.lock();
        let (avg, cnt) = &mut *data;

        *cnt += 1;
        *avg = (1.0 / *cnt as f64) * value + (1.0 - 1.0 / *cnt as f64);
    }
}

pub struct Statistics {
    avg_nr_dirty_pages: RunningAverage,
}

impl Statistics {
    pub fn new() -> Self {
        Self {
            avg_nr_dirty_pages: RunningAverage::new(),
        }
    }

    pub fn update_nr_dirty_pages(&self, nr_dirty_pages: usize) {
        self.avg_nr_dirty_pages.update(nr_dirty_pages as _);
    }

    pub fn avg_nr_dirty_pages(&self) -> f64 {
        self.avg_nr_dirty_pages.get()
    }
}
