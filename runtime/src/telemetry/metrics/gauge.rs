use prometheus_client::{
    encoding::{EncodeMetric, MetricEncoder},
    metrics::{MetricType, TypedMetric},
};
#[cfg(not(target_has_atomic = "64"))]
use std::sync::atomic::AtomicI32;
#[cfg(target_has_atomic = "64")]
use std::sync::atomic::AtomicI64;
use std::{
    marker::PhantomData,
    sync::{atomic::Ordering, Arc},
};

/// Native integer width used by [`Gauge`] on this target.
///
/// `i64` on platforms with 64-bit atomics, `i32` otherwise.
#[cfg(target_has_atomic = "64")]
pub type GaugeValue = i64;
#[cfg(not(target_has_atomic = "64"))]
pub type GaugeValue = i32;

#[cfg(target_has_atomic = "64")]
type GaugeAtomic = AtomicI64;
#[cfg(not(target_has_atomic = "64"))]
type GaugeAtomic = AtomicI32;

/// Native gauge metric.
#[derive(Debug)]
pub struct Gauge<N = GaugeValue> {
    value: Arc<GaugeAtomic>,
    _value: PhantomData<N>,
}

impl<N> Clone for Gauge<N> {
    fn clone(&self) -> Self {
        Self {
            value: self.value.clone(),
            _value: PhantomData,
        }
    }
}

impl<N> Default for Gauge<N> {
    fn default() -> Self {
        Self {
            value: Arc::new(GaugeAtomic::default()),
            _value: PhantomData,
        }
    }
}

impl Gauge<GaugeValue> {
    /// Increase the gauge by 1, returning the previous value.
    pub fn inc(&self) -> GaugeValue {
        self.inc_by(1)
    }

    /// Increase the gauge by `value`, returning the previous value.
    pub fn inc_by(&self, value: GaugeValue) -> GaugeValue {
        self.value.fetch_add(value, Ordering::Relaxed)
    }

    /// Decrease the gauge by 1, returning the previous value.
    pub fn dec(&self) -> GaugeValue {
        self.dec_by(1)
    }

    /// Decrease the gauge by `value`, returning the previous value.
    pub fn dec_by(&self, value: GaugeValue) -> GaugeValue {
        self.value.fetch_sub(value, Ordering::Relaxed)
    }

    /// Set the gauge to `value`, returning the previous value.
    pub fn set(&self, value: GaugeValue) -> GaugeValue {
        self.value.swap(value, Ordering::Relaxed)
    }

    /// Get the current gauge value.
    pub fn get(&self) -> GaugeValue {
        self.value.load(Ordering::Relaxed)
    }

    /// Atomically raise the gauge to at least `value`, returning the previous value.
    pub fn set_max(&self, value: GaugeValue) -> GaugeValue {
        self.value.fetch_max(value, Ordering::Relaxed)
    }

    /// Set a gauge from a lossless integer conversion.
    pub fn try_set<T: TryInto<GaugeValue>>(&self, value: T) -> Result<GaugeValue, T::Error> {
        let value = value.try_into()?;
        Ok(self.set(value))
    }

    /// Atomically raise the gauge to at least the provided value.
    pub fn try_set_max<T: TryInto<GaugeValue> + Copy>(
        &self,
        value: T,
    ) -> Result<GaugeValue, T::Error> {
        let value = value.try_into()?;
        Ok(self.set_max(value))
    }
}

impl<N> TypedMetric for Gauge<N> {
    const TYPE: MetricType = MetricType::Gauge;
}

impl EncodeMetric for Gauge<GaugeValue> {
    fn encode(&self, mut encoder: MetricEncoder<'_>) -> Result<(), std::fmt::Error> {
        encoder.encode_gauge(&self.get())
    }

    fn metric_type(&self) -> MetricType {
        <Self as TypedMetric>::TYPE
    }
}
