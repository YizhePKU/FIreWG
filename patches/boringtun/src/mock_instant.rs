pub struct MockClock;

use std::{cell::Cell, sync::Mutex};

use hifitime::{self, Epoch, UNIX_REF_EPOCH};

static CURRENT_TIME: Mutex<Cell<Epoch>> = Mutex::new(Cell::new(UNIX_REF_EPOCH));

impl MockClock {
    pub fn advance_std(duration: std::time::Duration) {
        let now = Self::now();
        let step = hifitime::Duration::from_total_nanoseconds(duration.as_nanos() as i128);
        CURRENT_TIME.lock().unwrap().replace(now + step);
    }

    pub fn advance(duration: hifitime::Duration) {
        let now = Self::now();
        CURRENT_TIME.lock().unwrap().replace(now + duration);
    }

    pub fn now() -> Epoch {
        CURRENT_TIME.lock().unwrap().get()
    }
}
