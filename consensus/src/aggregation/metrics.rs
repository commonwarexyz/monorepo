use commonware_runtime::{
    metrics::{Counter, Gauge},
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics, Registered,
};
use std::sync::Arc;

/// Metrics for the [super::Engine].
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Lowest height without a certificate
    pub tip: Registered<Gauge>,
    /// Number of digests returned by the automaton by status
    pub digest: Registered<status::Counter>,
    /// Number of [super::types::Ack] messages processed by status
    pub acks: Registered<status::Counter>,
    /// Number of certificates produced
    pub certificates: Registered<Counter>,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: Registered<status::Counter>,
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
            status::Counter::default(),
        );
        let acks = context.register(
            "acks",
            "Number of Ack messages processed by status",
            status::Counter::default(),
        );
        let certificates = context.counter("certificates", "Number of certificates produced");
        let rebroadcast = context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            status::Counter::default(),
        );
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
            rebroadcast,
            digest_duration: histogram::Timed::new(digest_duration, clock),
        }
    }
}
