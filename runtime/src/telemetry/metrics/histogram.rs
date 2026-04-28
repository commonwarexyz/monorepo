//! Utilities for working with histograms.

use super::{raw, Histogram};
use crate::Clock;
use std::time::SystemTime;

/// Convenience methods for Prometheus histograms.
pub trait HistogramExt {
    /// Observe the duration between two points in time, in seconds.
    ///
    /// If the clock goes backwards, the duration is 0.
    fn observe_between(&self, start: SystemTime, end: SystemTime);
}

impl HistogramExt for raw::Histogram {
    fn observe_between(&self, start: SystemTime, end: SystemTime) {
        let duration = end
            .duration_since(start)
            .map_or(0.0, |duration| duration.as_secs_f64());
        self.observe(duration);
    }
}

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

/// A wrapper around a histogram that can time operations using a caller-provided clock.
#[derive(Clone)]
pub struct Timed {
    /// The histogram to record durations in.
    histogram: Histogram,
}

impl Timed {
    /// Create a new timed histogram.
    pub const fn new(histogram: Histogram) -> Self {
        Self { histogram }
    }

    /// Create a new timer that can record a duration from the current time.
    pub fn timer<C: Clock>(&self, clock: &C) -> Timer {
        let start = clock.current();
        Timer {
            histogram: self.histogram.clone(),
            start,
        }
    }

    /// Time an operation, recording only if it returns `Some`.
    pub fn time_some<C: Clock, T, F: FnOnce() -> Option<T>>(&self, clock: &C, f: F) -> Option<T> {
        let start = clock.current();
        let result = f();
        if result.is_some() {
            self.histogram.observe_between(start, clock.current());
        }
        result
    }
}

/// A timer that records a duration when explicitly observed.
pub struct Timer {
    /// The histogram to record durations in.
    histogram: Histogram,

    /// The time at which the timer was started.
    start: SystemTime,
}

impl Timer {
    /// Record the duration using the given clock.
    pub fn observe<C: Clock>(self, clock: &C) {
        self.histogram.observe_between(self.start, clock.current());
    }
}
