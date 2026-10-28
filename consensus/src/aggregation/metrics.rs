use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _, histogram, status},
};

/// Metrics for the [super::Engine].
pub struct Metrics {
    /// Lowest height without a certificate while incomplete; equals the last height when complete
    pub frontier: Gauge,
    /// Whether the full configured range is certified
    pub complete: Gauge,
    /// Number of digests returned by the automaton by status
    pub digest: status::Counter,
    /// Number of [super::types::Ack] messages processed by status
    pub acks: status::Counter,
    /// Number of certificates accepted
    pub certificates: Counter,
    /// Histogram of application digest durations
    pub digest_duration: histogram::Timed,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: &impl RuntimeMetrics) -> Self {
        let frontier = context.gauge(
            "frontier",
            "Lowest uncertified position while incomplete; last position when complete",
        );
        let complete = context.gauge("complete", "Whether the full configured range is certified");
        let digest = context.family(
            "digest",
            "Number of digests returned by the automaton by status",
        );
        let acks = context.family("acks", "Number of Ack messages processed by status");
        let certificates = context.counter("certificates", "Number of certificates accepted");
        let digest_duration = context.histogram(
            "digest_duration",
            "Histogram of application digest durations",
            histogram::Buckets::LOCAL,
        );

        Self {
            frontier,
            complete,
            digest,
            acks,
            certificates,
            digest_duration: histogram::Timed::new(digest_duration),
        }
    }
}
