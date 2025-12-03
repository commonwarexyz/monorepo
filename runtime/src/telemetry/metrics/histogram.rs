//! Utilities for working with histograms.

use crate::Clock;
use prometheus_client::metrics::histogram::Histogram;
use std::{sync::Arc, time::SystemTime};

/// Holds constants for bucket sizes for histograms.
///
/// The bucket sizes are in seconds.
pub struct Buckets;

impl Buckets {
    /// For resolving items over a network.
    ///
    /// These tasks could either be between two peers or require multiple hops, rounds, retries,
    /// etc.
    pub const NETWORK: [f64; 13] = [
        0.010, 0.020, 0.050, 0.100, 0.200, 0.500, 1.0, 2.0, 5.0, 10.0, 30.0, 60.0, 300.0,
    ];

    /// For resolving items locally.
    ///
    /// These tasks are expected to be fast and not require network access, but might require
    /// expensive computation, disk access, etc.
    pub const LOCAL: [f64; 12] = [
        3e-6, 1e-5, 3e-5, 1e-4, 3e-4, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0,
    ];

    /// For cryptographic operations.
    ///
    /// These operations are expected to be fast and not require network access, but might
    /// require expensive computation.
    pub const CRYPTOGRAPHY: [f64; 16] = [
        3e-6, 1e-5, 3e-5, 1e-4, 3e-4, 0.001, 0.002, 0.003, 0.005, 0.01, 0.015, 0.02, 0.025, 0.03,
        0.1, 0.2,
    ];
}

/// Extension trait for histograms.
pub trait HistogramExt {
    /// Observe the duration between two points in time, in seconds.
    ///
    /// If the clock goes backwards, the duration is 0.
    fn observe_between(&self, start: SystemTime, end: SystemTime);
}

impl HistogramExt for Histogram {
    fn observe_between(&self, start: SystemTime, end: SystemTime) {
        let duration = end.duration_since(start).map_or(
            // Clock went backwards
            0.0,
            |duration| duration.as_secs_f64(),
        );
        self.observe(duration);
    }
}

/// A wrapper around a histogram that includes a clock.
#[derive(Clone)]
pub struct Timed<C: Clock> {
    /// The histogram to record durations in.
    histogram: Histogram,

    /// The clock to use for recording durations.
    clock: Arc<C>,
}

impl<C: Clock> Timed<C> {
    /// Create a new timed histogram.
    pub const fn new(histogram: Histogram, clock: Arc<C>) -> Self {
        Self { histogram, clock }
    }

    /// Create a new timer that can record a duration from the current time.
    pub fn timer(&self) -> Timer<C> {
        let start = self.clock.current();
        Timer {
            histogram: self.histogram.clone(),
            clock: self.clock.clone(), // Arc clone
            start,
            canceled: false,
        }
    }

    /// Time an operation, recording only if it returns `Some`.
    pub fn time_some<T, F: FnOnce() -> Option<T>>(&self, f: F) -> Option<T> {
        let start = self.clock.current();
        let result = f();
        if result.is_some() {
            self.histogram.observe_between(start, self.clock.current());
        }
        result
    }
}

/// A timer that records a duration when dropped.
pub struct Timer<C: Clock> {
    /// The histogram to record durations in.
    histogram: Histogram,

    /// The clock to use for recording durations.
    clock: Arc<C>,

    /// The time at which the timer was started.
    start: SystemTime,

    /// Whether the timer was canceled.
    canceled: bool,
}

impl<C: Clock> Timer<C> {
    /// Record the duration and cancel the timer.
    pub fn observe(&mut self) {
        self.canceled = true;
        let end = self.clock.current();
        self.histogram.observe_between(self.start, end);
    }

    /// Cancel the timer, preventing the duration from being recorded when dropped.
    pub fn cancel(mut self) {
        self.canceled = true;
    }
}

impl<C: Clock> Drop for Timer<C> {
    fn drop(&mut self) {
        if self.canceled {
            return;
        }
        self.observe();
    }
}
