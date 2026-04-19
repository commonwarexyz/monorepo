use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Metrics as RuntimeMetrics,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};

/// Metrics for the [super::Engine].
pub struct Metrics {
    /// Lowest height without a certificate
    pub tip: Gauge,
    /// Number of digests returned by the automaton by status
    pub digest: status::Counter,
    /// Number of [super::types::Ack] messages processed by status
    pub acks: status::Counter,
    /// Number of certificates produced
    pub certificates: Counter,
    /// Histogram of application digest durations
    pub digest_duration: histogram::Timed,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let _ = context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            status::Counter::default(),
        );
        let digest_duration = context.register(
            "digest_duration",
            "Histogram of application digest durations",
            Histogram::new(histogram::Buckets::LOCAL),
        );
        Self {
            tip: context.register(
                "tip",
                "Lowest height without a certificate",
                Gauge::default(),
            ),
            digest: context.register(
                "digest",
                "Number of digests returned by the automaton by status",
                status::Counter::default(),
            ),
            acks: context.register(
                "acks",
                "Number of Ack messages processed by status",
                status::Counter::default(),
            ),
            certificates: context.register(
                "certificates",
                "Number of certificates produced",
                Counter::default(),
            ),
            digest_duration: histogram::Timed::new(digest_duration),
        }
    }
}
