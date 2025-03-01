use crate::Clock;
use prometheus_client::metrics::histogram::Histogram;
use std::time::SystemTime;

/// Holds constants for bucket sizes for histograms.
///
/// The bucket sizes are in seconds.
pub struct Buckets;

impl Buckets {
    /// For roundtrip requests to a peer.
    pub const P2P: [f64; 12] = [
        0.005, 0.01, 0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0,
    ];

    /// For resolving items over a network.
    ///
    /// These tasks might require multiple peers, hops, rounds, retries, etc.
    pub const NETWORK: [f64; 12] = [
        0.02, 0.05, 0.1, 0.2, 0.5, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0,
    ];

    /// For resolving items locally.
    ///
    /// These tasks are expected to be fast and not require network access, but might require
    /// expensive computation, disk access, etc.
    pub const LOCAL: [f64; 12] = [
        3e-6, 1e-5, 3e-5, 1e-4, 3e-4, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0,
    ];
}

/// Extension trait for histograms.
pub trait HistogramExt {
    fn guard<'a, C: Clock>(&'a self, clock: &'a C) -> HistogramGuard<'a, C>;

    /// Observe the duration between two points in time, in seconds.
    ///
    /// If the clock goes backwards, the duration is 0.
    fn observe_between(&self, start: SystemTime, end: SystemTime);
}

impl HistogramExt for Histogram {
    fn guard<'a, C: Clock>(&'a self, clock: &'a C) -> HistogramGuard<'a, C> {
        HistogramGuard {
            histogram: self,
            clock,
            start: clock.current(),
            recorded: false,
        }
    }

    fn observe_between(&self, start: SystemTime, end: SystemTime) {
        let duration = match end.duration_since(start) {
            Ok(duration) => duration.as_secs_f64(),
            Err(_) => 0.0, // Clock went backwards
        };
        self.observe(duration);
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
            self.histogram
                .observe_between(self.start, self.clock.current());
            self.recorded = true;
        }
    }
}

impl<C: Clock> Drop for HistogramGuard<'_, C> {
    fn drop(&mut self) {
        self.record();
    }
}
