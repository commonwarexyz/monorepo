//! Utilities for working with histograms.

use crate::Clock;
use commonware_utils::sync::Mutex;
use prometheus_client::{
    encoding::{EncodeMetric, MetricEncoder, NoLabelSet},
    metrics::{MetricType, TypedMetric},
};
use std::{fmt::Write, iter::once, sync::Arc, time::SystemTime};

/// Native histogram metric.
///
/// Sources:
/// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/metrics/histogram.rs#L36-L183
/// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/encoding/text.rs#L399-L466
///
/// This mirrors upstream histogram semantics: buckets include a final
/// `+Inf` bucket, observations update sum/count and the first matching bucket,
/// and generic `EncodeMetric` delegates to `MetricEncoder::encode_histogram`.
/// It is not a direct copy: upstream uses an `RwLock` read guard and exposes
/// bucket helpers/exemplar hooks, while this keeps the runtime's smaller API
/// and adds a direct text sample encoder for registered native histograms.
#[derive(Clone, Debug)]
pub struct Histogram {
    inner: Arc<Mutex<Inner>>,
}

#[derive(Debug)]
struct Inner {
    sum: f64,
    count: u64,
    buckets: Vec<(f64, u64)>,
}

impl Histogram {
    /// Create a new histogram with the provided bucket upper bounds.
    pub fn new(buckets: impl IntoIterator<Item = f64>) -> Self {
        Self {
            inner: Arc::new(Mutex::new(Inner {
                sum: 0.0,
                count: 0,
                buckets: buckets
                    .into_iter()
                    .chain(once(f64::MAX))
                    .map(|upper_bound| (upper_bound, 0))
                    .collect(),
            })),
        }
    }

    /// Observe a value.
    pub fn observe(&self, value: f64) {
        let mut inner = self.inner.lock();
        inner.sum += value;
        inner.count += 1;
        if let Some((_, count)) = inner
            .buckets
            .iter_mut()
            .find(|(upper_bound, _)| *upper_bound >= value)
        {
            *count += 1;
        }
    }

    pub(crate) fn snapshot(&self) -> (f64, u64, Vec<(f64, u64)>) {
        let inner = self.inner.lock();
        (inner.sum, inner.count, inner.buckets.clone())
    }

    pub(crate) fn bucket_bounds(&self) -> Vec<f64> {
        self.inner
            .lock()
            .buckets
            .iter()
            .map(|(upper_bound, _)| *upper_bound)
            .collect()
    }

    pub(crate) fn encode_samples(
        &self,
        sum_prefix: &str,
        count_prefix: &str,
        bucket_prefixes: &[String],
        samples: &mut String,
    ) -> Result<(), std::fmt::Error> {
        let inner = self.inner.lock();

        samples.push_str(sum_prefix);
        samples.push_str(dtoa::Buffer::new().format(inner.sum));
        samples.push('\n');

        samples.push_str(count_prefix);
        write!(samples, "{}", inner.count)?;
        samples.push('\n');

        let mut cumulative = 0;
        for ((_, count), bucket_prefix) in inner.buckets.iter().zip(bucket_prefixes) {
            cumulative += *count;
            samples.push_str(bucket_prefix);
            write!(samples, "{cumulative}")?;
            samples.push('\n');
        }

        Ok(())
    }

    /// Observe the duration between two points in time, in seconds.
    ///
    /// If the clock goes backwards, the duration is 0.
    pub fn observe_between(&self, start: SystemTime, end: SystemTime) {
        let duration = end
            .duration_since(start)
            .map_or(0.0, |duration| duration.as_secs_f64());
        self.observe(duration);
    }
}

impl TypedMetric for Histogram {
    const TYPE: MetricType = MetricType::Histogram;
}

impl EncodeMetric for Histogram {
    fn encode(&self, mut encoder: MetricEncoder<'_>) -> Result<(), std::fmt::Error> {
        let (sum, count, buckets) = self.snapshot();
        encoder.encode_histogram::<NoLabelSet>(sum, count, &buckets, None)
    }

    fn metric_type(&self) -> MetricType {
        Self::TYPE
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

/// A wrapper around a histogram that includes a clock.
#[derive(Clone)]
pub struct Timed<C: Clock> {
    /// The histogram to record durations in.
    histogram: super::Histogram,

    /// The clock to use for recording durations.
    clock: Arc<C>,
}

impl<C: Clock> Timed<C> {
    /// Create a new timed histogram.
    pub const fn new(histogram: super::Histogram, clock: Arc<C>) -> Self {
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
    histogram: super::Histogram,

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
