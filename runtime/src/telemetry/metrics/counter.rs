use prometheus_client::{
    encoding::{EncodeMetric, MetricEncoder, NoLabelSet},
    metrics::{MetricType, TypedMetric},
};
#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::AtomicU32;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicU64;
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, Arc},
};

/// Native integer width used by [`Counter`] on this target.
///
/// `u64` on platforms with 64-bit atomics, `u32` otherwise.
#[cfg(target_has_atomic = "64")]
pub type CounterValue = u64;
#[cfg(not(target_has_atomic = "64"))]
pub type CounterValue = u32;

#[cfg(target_has_atomic = "64")]
type CounterAtomic = AtomicU64;
#[cfg(not(target_has_atomic = "64"))]
type CounterAtomic = AtomicU32;

/// Native counter metric.
///
/// Source:
/// https://github.com/prometheus/client_rust/blob/4a6d40a55443d5b18f5be311d246c03e56f417d6/src/metrics/counter.rs#L43-L213
///
/// This mirrors the default upstream counter behavior: shared atomic storage,
/// relaxed increments/loads, and `EncodeMetric` delegation to
/// `MetricEncoder::encode_counter`. It is not a direct copy: upstream supports
/// generic atomic backends, floating-point counters, const counters, and direct
/// access to the inner atomic. The runtime only needs one concrete integer
/// shape so registration can downcast it into a native fast path.
#[derive(Debug)]
pub struct Counter<N = CounterValue> {
    value: Arc<CounterAtomic>,
    _value: PhantomData<N>,
}

impl<N> Clone for Counter<N> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            _value: PhantomData,
        }
    }
}

impl<N> Default for Counter<N> {
    fn default() -> Self {
        Self {
            value: Arc::new(CounterAtomic::default()),
            _value: PhantomData,
        }
    }
}

impl Counter<CounterValue> {
    /// Increase the counter by 1, returning the previous value.
    pub fn inc(&self) -> CounterValue {
        self.inc_by(1)
    }

    /// Increase the counter by `value`, returning the previous value.
    pub fn inc_by(&self, value: CounterValue) -> CounterValue {
        self.value.fetch_add(value, Ordering::Relaxed)
    }

    /// Get the current counter value.
    pub fn get(&self) -> CounterValue {
        self.value.load(Ordering::Relaxed)
    }
}

impl<N> TypedMetric for Counter<N> {
    const TYPE: MetricType = MetricType::Counter;
}

impl EncodeMetric for Counter<CounterValue> {
    fn encode(&self, mut encoder: MetricEncoder<'_>) -> Result<(), std::fmt::Error> {
        encoder.encode_counter::<NoLabelSet, _, u64>(&self.get(), None)
    }

    fn metric_type(&self) -> MetricType {
        <Self as TypedMetric>::TYPE
    }
}
