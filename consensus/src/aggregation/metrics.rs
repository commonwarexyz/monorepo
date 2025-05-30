use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
use std::sync::Arc;

/// Metrics for the [`Engine`](super::Engine)
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Lowest index without a threshold signature
    pub tip: Gauge,
    /// Number of verifies processed by status
    pub verify: status::Counter,
    /// Number of [`Ack`](super::types::Ack) messages processed by status
    pub acks: status::Counter,
    /// Number of threshold signatures produced
    pub threshold: Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
    /// Histogram of application verification durations
    pub verify_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let clock = Arc::new(context.clone());
        let verify_duration = Histogram::new(histogram::Buckets::LOCAL.into_iter());
        let metrics = Self {
            tip: Gauge::default(),
            verify: status::Counter::default(),
            acks: status::Counter::default(),
            threshold: Counter::default(),
            rebroadcast: status::Counter::default(),
            verify_duration: histogram::Timed::new(verify_duration.clone(), clock.clone()),
        };
        context.register(
            "tip",
            "Lowest index without a threshold signature",
            metrics.tip.clone(),
        );
        context.register(
            "verify",
            "Number of verifies processed by status",
            metrics.verify.clone(),
        );
        context.register(
            "acks",
            "Number of Ack messages processed by status",
            metrics.acks.clone(),
        );
        context.register(
            "threshold",
            "Number of threshold signatures produced",
            metrics.threshold.clone(),
        );
        context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            metrics.rebroadcast.clone(),
        );
        context.register(
            "verify_duration",
            "Histogram of application verification durations",
            verify_duration,
        );
        metrics
    }
}
