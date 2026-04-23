use commonware_runtime::{
    telemetry::metrics::{histogram, status, Counter, Gauge, MetricsExt as _},
    Clock, Metrics as RuntimeMetrics,
};
use std::sync::Arc;

/// Metrics for the [super::Engine].
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Lowest height without a certificate
    pub tip: Gauge,
    /// Number of digests returned by the automaton by status
    pub digest: status::Counter,
    /// Number of [super::types::Ack] messages processed by status
    pub acks: status::Counter,
    /// Number of certificates produced
    pub certificates: Counter,
    /// Histogram of application digest durations
    pub digest_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let tip = context.gauge("tip", "Lowest height without a certificate");
        let digest = context.register(
            "digest",
            "Number of digests returned by the automaton by status",
            status::Raw::default(),
        );
        let acks = context.register(
            "acks",
            "Number of Ack messages processed by status",
            status::Raw::default(),
        );
        let certificates = context.counter("certificates", "Number of certificates produced");
        let digest_duration = context.histogram(
            "digest_duration",
            "Histogram of application digest durations",
            histogram::Buckets::LOCAL,
        );
        let clock = Arc::new(context);

        Self {
            tip,
            digest,
            acks,
            certificates,
            digest_duration: histogram::Timed::new(digest_duration, clock),
        }
    }
}
