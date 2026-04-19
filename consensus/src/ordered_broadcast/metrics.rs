use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Metrics as RuntimeMetrics,
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
};

/// Label for sequencer height metrics
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct SequencerLabel {
    /// Hex representation of the sequencer's public key
    pub sequencer: String,
}

impl SequencerLabel {
    /// Create a new sequencer label from a public key
    pub fn from<P: PublicKey>(sequencer: &P) -> Self {
        Self {
            sequencer: sequencer.to_string(),
        }
    }
}

/// Metrics for the [super::Engine]
pub struct Metrics {
    /// Height per sequencer
    pub sequencer_heights: Family<SequencerLabel, Gauge>,
    /// Number of acks processed by status
    pub acks: status::Counter,
    /// Number of nodes processed by status
    pub nodes: status::Counter,
    /// Number of application verifications by status
    pub verify: status::Counter,
    /// Number of certificates produced
    pub certificates: Counter,
    /// Number of propose attempts by status
    pub propose: status::Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
    /// Histogram of application verification durations
    pub verify_duration: histogram::Timed,
    /// Histogram of time from new proposal to certificate generation
    pub e2e_duration: histogram::Timed,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let verify_duration = context.register(
            "verify_duration",
            "Histogram of application verification durations",
            Histogram::new(histogram::Buckets::LOCAL),
        );
        let e2e_duration = context.register(
            "e2e_duration",
            "Histogram of time from new proposal to certificate generation",
            Histogram::new(histogram::Buckets::NETWORK),
        );
        Self {
            sequencer_heights: context.register(
                "sequencer_heights",
                "Height per sequencer tracked",
                Family::default(),
            ),
            acks: context.register(
                "acks",
                "Number of acks processed by status",
                status::Counter::default(),
            ),
            nodes: context.register(
                "nodes",
                "Number of nodes processed by status",
                status::Counter::default(),
            ),
            verify: context.register(
                "verify",
                "Number of application verifications by status",
                status::Counter::default(),
            ),
            certificates: context.register(
                "certificates",
                "Number of certificates produced",
                Counter::default(),
            ),
            propose: context.register(
                "propose",
                "Number of propose attempts by status",
                status::Counter::default(),
            ),
            rebroadcast: context.register(
                "rebroadcast",
                "Number of rebroadcast attempts by status",
                status::Counter::default(),
            ),
            verify_duration: histogram::Timed::new(verify_duration),
            e2e_duration: histogram::Timed::new(e2e_duration),
        }
    }
}
