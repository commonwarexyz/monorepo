use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
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
        let tip =
            context.get_or_register_default::<Gauge>("tip", "Lowest height without a certificate");
        let digest = context.get_or_register_default::<status::Counter>(
            "digest",
            "Number of digests returned by the automaton by status",
        );
        let acks = context.get_or_register_default::<status::Counter>(
            "acks",
            "Number of Ack messages processed by status",
        );
        let certificates = context
            .get_or_register_default::<Counter>("certificates", "Number of certificates produced");
        let digest_duration = context.get_or_register_with(
            "digest_duration",
            "Histogram of application digest durations",
            || Histogram::new(histogram::Buckets::LOCAL),
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
