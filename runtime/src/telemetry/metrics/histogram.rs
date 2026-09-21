//! Utilities for working with histograms.

use super::{Histogram, MetricsExt as _, raw};
use crate::{Clock, Metrics};
use std::{
    future::Future,
    sync::Arc,
    time::{Duration, SystemTime},
};

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

    /// Register a duration histogram (see [`duration_histogram`]) wrapped for timing.
    pub fn register<M: Metrics>(context: &M, name: &'static str, help: &'static str) -> Self {
        Self::new(duration_histogram(context, name, help))
    }

    /// Create a new timer that can record a duration from the current time.
    pub fn timer<C: Clock>(&self, clock: &C) -> Timer {
        let start = clock.current();
        Timer {
            histogram: self.histogram.clone(),
            start,
        }
    }

    /// Time an operation, recording a sample only if it resolves to `Some`.
    pub async fn time_some<C: Clock, T>(
        &self,
        clock: &C,
        op: impl Future<Output = Option<T>>,
    ) -> Option<T> {
        let start = clock.current();
        let result = op.await;
        if result.is_some() {
            self.histogram.observe_between(start, clock.current());
        }
        result
    }

    /// Start a timer guard that observes the elapsed duration when dropped.
    pub fn scoped<C: Clock>(&self, clock: &Arc<C>) -> ScopedTimer<C> {
        ScopedTimer {
            timer: Some(self.timer(clock.as_ref())),
            clock: clock.clone(),
        }
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

/// A timer guard that observes its duration when dropped.
///
/// Built on top of [`Timer`]. Useful for `?`-heavy async code where every early-return path
/// would otherwise need to remember to call [`Timer::observe`]. Validation failures after the
/// guard is created are still part of the recorded duration; if a code path should not record
/// a sample, call [`ScopedTimer::cancel`] before the guard is dropped.
pub struct ScopedTimer<C: Clock> {
    timer: Option<Timer>,
    clock: Arc<C>,
}

impl<C: Clock> ScopedTimer<C> {
    /// Cancel the guard so it does not observe a sample on drop.
    pub fn cancel(mut self) {
        self.timer = None;
    }
}

impl<C: Clock> Drop for ScopedTimer<C> {
    fn drop(&mut self) {
        if let Some(timer) = self.timer.take() {
            timer.observe(self.clock.as_ref());
        }
    }
}

/// Accumulates separate work intervals into a single duration sample.
///
/// Time between intervals is excluded. Call [`Self::observe`] to record the total.
#[derive(Default)]
pub struct Accumulator {
    duration: Option<Duration>,
}

impl Accumulator {
    /// Add an interval, treating a backwards clock as a zero duration.
    ///
    /// The total saturates at [`Duration::MAX`].
    pub fn add_between(&mut self, start: SystemTime, end: SystemTime) {
        let duration = end.duration_since(start).unwrap_or_default();
        let total = self.duration.get_or_insert(Duration::ZERO);
        *total = total.saturating_add(duration);
    }

    /// Record the total in seconds and reset the accumulator.
    ///
    /// Does nothing if no intervals have been added since the last observation.
    pub fn observe(&mut self, histogram: &raw::Histogram) {
        if let Some(duration) = self.duration.take() {
            histogram.observe(duration.as_secs_f64());
        }
    }
}

/// Register a duration histogram using [`Buckets::LOCAL`] (storage-style work).
pub fn duration_histogram<M: Metrics>(
    context: &M,
    name: &'static str,
    help: &'static str,
) -> Histogram {
    context.histogram(name, help, Buckets::LOCAL)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Runner as _, Supervisor as _, deterministic};

    #[test]
    fn accumulated_duration_records_one_sum() {
        deterministic::Runner::default().start(|context| async move {
            let histogram = context.histogram("duration", "work duration", [1.0, 4.0, 6.0]);
            let mut accumulated = Accumulator::default();
            let start = context.current();

            accumulated.observe(&histogram);
            assert!(context.encode().contains("duration_count 0\n"));

            accumulated.add_between(start, start + Duration::from_secs(2));
            accumulated.add_between(
                start + Duration::from_secs(20),
                start + Duration::from_secs(23),
            );
            assert!(context.encode().contains("duration_count 0\n"));
            accumulated.observe(&histogram);
            let metrics = context.encode();
            assert!(metrics.contains("duration_count 1\n"), "{metrics}");
            assert!(metrics.contains("duration_sum 5.0\n"), "{metrics}");
            assert!(
                metrics.contains("duration_bucket{le=\"4.0\"} 0\n"),
                "{metrics}"
            );
            assert!(
                metrics.contains("duration_bucket{le=\"6.0\"} 1\n"),
                "{metrics}"
            );

            accumulated.observe(&histogram);
            assert_eq!(context.encode(), metrics);

            accumulated.add_between(start, start + Duration::from_secs(1));
            accumulated.observe(&histogram);
            let metrics = context.encode();
            assert!(metrics.contains("duration_count 2\n"), "{metrics}");
            assert!(metrics.contains("duration_sum 6.0\n"), "{metrics}");
        });
    }

    #[test]
    fn accumulated_duration_records_zero_and_backwards_intervals() {
        deterministic::Runner::default().start(|context| async move {
            let histogram = raw::Histogram::new(Buckets::LOCAL);
            let _registered = context.register("duration", "work duration", histogram.clone());
            let start = context.current();
            for end in [start, start - Duration::from_secs(1)] {
                let mut accumulated = Accumulator::default();
                accumulated.add_between(start, end);
                accumulated.observe(&histogram);
            }
            let metrics = context.encode();
            assert!(metrics.contains("duration_count 2\n"), "{metrics}");
            assert!(metrics.contains("duration_sum 0.0\n"), "{metrics}");
        });
    }

    #[test]
    fn accumulated_duration_saturates() {
        deterministic::Runner::default().start(|context| async move {
            let histogram = duration_histogram(&context, "duration", "work duration");
            let mut accumulated = Accumulator {
                duration: Some(Duration::MAX - Duration::from_millis(1)),
            };
            let start = context.current();
            accumulated.add_between(start, start + Duration::from_secs(1));
            accumulated.observe(&histogram);
            let metrics = context.encode();
            assert!(metrics.contains("duration_count 1\n"), "{metrics}");
            let sum: f64 = metrics
                .lines()
                .find_map(|line| line.strip_prefix("duration_sum "))
                .unwrap()
                .parse()
                .unwrap();
            assert_eq!(sum, Duration::MAX.as_secs_f64());
        });
    }

    #[test]
    fn duration_records_all_calls() {
        deterministic::Runner::default().start(|context| async move {
            let histogram = duration_histogram(&context, "test_duration", "test duration");
            let timed = Timed::new(histogram);
            let clock = Arc::new(context.child("timer"));

            {
                let _timer = timed.scoped(&clock);
                context.sleep(Duration::from_millis(1)).await;
                let result: Result<(), ()> = Ok(());
                assert!(result.is_ok());
            }

            {
                let _timer = timed.scoped(&clock);
                context.sleep(Duration::from_millis(1)).await;
                let result: Result<(), ()> = Err(());
                assert!(result.is_err());
            }

            {
                let _timer = timed.scoped(&clock);
                context.sleep(Duration::from_millis(1)).await;
            }

            let metrics = context.encode();
            assert!(
                metrics.contains("test_duration_count 3"),
                "unexpected metrics: {metrics}"
            );
        });
    }
}
