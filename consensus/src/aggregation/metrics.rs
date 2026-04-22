use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics, Registered,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
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
    pub digest_duration: histogram::Timed<E, Registered<Histogram>>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let tip = context.register(
            "tip",
            "Lowest height without a certificate",
            Gauge::default(),
        );
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
        let certificates = context.register(
            "certificates",
            "Number of certificates produced",
            Counter::default(),
        );
        let rebroadcast = context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            status::Counter::default(),
        );
        let digest_duration = context.register(
            "digest_duration",
            "Histogram of application digest durations",
            Histogram::new(histogram::Buckets::LOCAL),
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
