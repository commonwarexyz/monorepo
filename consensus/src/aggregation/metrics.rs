use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
use std::sync::Arc;

/// Metrics for the [super::Engine].
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Lowest index without a threshold signature
    pub tip: Gauge,
    /// Number of digests returned by the automaton by status
    pub digest: status::Counter,
    /// Number of [super::types::Ack] messages processed by status
    pub acks: status::Counter,
    /// Number of threshold signatures produced
    pub threshold: Counter,
    /// Histogram of application digest durations
    pub digest_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let tip = Gauge::default();
        context.register(
            "tip",
            "Lowest index without a threshold signature",
            tip.clone(),
        );
        let digest = status::Counter::default();
        context.register(
            "digest",
            "Number of digests returned by the automaton by status",
            digest.clone(),
        );
        let acks = status::Counter::default();
        context.register(
            "acks",
            "Number of Ack messages processed by status",
            acks.clone(),
        );
        let threshold = Counter::default();
        context.register(
            "threshold",
            "Number of threshold signatures produced",
            threshold.clone(),
        );
        let rebroadcast = status::Counter::default();
        context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            rebroadcast.clone(),
        );
        let digest_duration = Histogram::new(histogram::Buckets::LOCAL.into_iter());
        context.register(
            "digest_duration",
            "Histogram of application digest durations",
            digest_duration.clone(),
        );
        let clock = Arc::new(context);

        Self {
            tip,
            digest,
            acks,
            threshold,
            digest_duration: histogram::Timed::new(digest_duration, clock),
        }
    }
}
