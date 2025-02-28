use crate::Clock;
use prometheus_client::metrics::histogram::Histogram;
use std::time::SystemTime;

pub struct Buckets;

impl Buckets {
    pub const NETWORK: [f64; 10] = [0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0];
}

pub trait HistogramExt<C: Clock> {
    fn guard<'a>(&'a self, clock: &'a C) -> HistogramGuard<'a, C>;
}

impl<C: Clock> HistogramExt<C> for Histogram {
    fn guard<'a>(&'a self, clock: &'a C) -> HistogramGuard<'a, C> {
        HistogramGuard {
            histogram: self,
            clock,
            start: clock.current(),
            recorded: false,
        }
    }
}

pub struct HistogramGuard<'a, C: Clock> {
    histogram: &'a Histogram,
    clock: &'a C,
    start: SystemTime,
    recorded: bool,
}

impl<C: Clock> HistogramGuard<'_, C> {
    pub fn observe(&mut self) {
        self.record();
    }

    pub fn cancel(&mut self) {
        self.recorded = true;
    }

    fn record(&mut self) {
        if !self.recorded {
            let duration = match self.clock.current().duration_since(self.start) {
                Ok(duration) => duration.as_secs_f64(),
                Err(_) => 0.0, // Clock went backwards
            };
            self.histogram.observe(duration);
            self.recorded = true;
        }
    }
}

impl<C: Clock> Drop for HistogramGuard<'_, C> {
    fn drop(&mut self) {
        self.record();
    }
}
