//! Utilities for working with histograms.
//!
//! # Examples
//!
//! ```
//! use commonware_runtime::{
//!     deterministic,
//!     telemetry::metrics::histogram::{Buckets, Timed},
//!     Clock, Runner,
//! };
//! use prometheus_client::metrics::histogram::Histogram;
//! use std::time::Duration;
//!
//! let runner = deterministic::Runner::default();
//! runner.start(|context| async move {
//!     let latency = Timed::new(Histogram::new(Buckets::LOCAL));
//!
//!     let started = latency.start(&context);
//!     context.sleep(Duration::from_millis(1)).await;
//!     started.record(&context);
//! });
//! ```

use crate::Clock;
use prometheus_client::metrics::histogram::Histogram;
use std::time::SystemTime;

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

/// A wrapper around a histogram that can time operations against a borrowed clock.
pub struct Timed {
    /// The histogram to record durations in.
    histogram: Histogram,
}

/// A sampled histogram observation.
///
/// This token is explicit: dropping it records nothing. Call [`Started::record`] to record
/// a duration.
#[must_use = "call record to record the timing, or drop it to skip recording"]
pub struct Started {
    /// The histogram to record durations in.
    histogram: Histogram,

    /// The time at which the observation began.
    start: SystemTime,
}

impl Clone for Timed {
    fn clone(&self) -> Self {
        Self {
            histogram: self.histogram.clone(),
        }
    }
}

impl Timed {
    /// Create a new timed histogram.
    pub const fn new(histogram: Histogram) -> Self {
        Self { histogram }
    }

    /// Sample the current time and return an explicit observation token.
    pub fn start<C: Clock + ?Sized>(&self, clock: &C) -> Started {
        Started {
            histogram: self.histogram.clone(),
            start: clock.current(),
        }
    }
}

impl Started {
    /// Record the observation against the current time of `clock`.
    pub fn record<C: Clock + ?Sized>(self, clock: &C) {
        self.histogram.observe_between(self.start, clock.current());
    }
}
