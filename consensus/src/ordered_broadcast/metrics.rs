use commonware_cryptography::PublicKey;
use commonware_runtime::{
    metrics::{Counter, EncodeLabelSet, Family, Gauge},
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics, Registered,
};
use std::sync::Arc;

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
pub struct Metrics<E: RuntimeMetrics + Clock> {
    /// Height per sequencer
    pub sequencer_heights: Registered<Family<SequencerLabel, Gauge>>,
    /// Number of acks processed by status
    pub acks: Registered<status::Counter>,
    /// Number of nodes processed by status
    pub nodes: Registered<status::Counter>,
    /// Number of application verifications by status
    pub verify: Registered<status::Counter>,
    /// Number of certificates produced
    pub certificates: Registered<Counter>,
    /// Number of propose attempts by status
    pub propose: Registered<status::Counter>,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: Registered<status::Counter>,
    /// Histogram of application verification durations
    pub verify_duration: histogram::Timed<E>,
    /// Histogram of time from new proposal to certificate generation
    pub e2e_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let sequencer_heights = context.family("sequencer_heights", "Height per sequencer tracked");
        let acks = context.register(
            "acks",
            "Number of acks processed by status",
            status::Counter::default(),
        );
        let nodes = context.register(
            "nodes",
            "Number of nodes processed by status",
            status::Counter::default(),
        );
        let verify = context.register(
            "verify",
            "Number of application verifications by status",
            status::Counter::default(),
        );
        let certificates = context.counter("certificates", "Number of certificates produced");
        let propose = context.register(
            "propose",
            "Number of propose attempts by status",
            status::Counter::default(),
        );
        let rebroadcast = context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            status::Counter::default(),
        );
        let verify_duration = context.histogram(
            "verify_duration",
            "Histogram of application verification durations",
            histogram::Buckets::LOCAL,
        );
        let e2e_duration = context.histogram(
            "e2e_duration",
            "Histogram of time from new proposal to certificate generation",
            histogram::Buckets::NETWORK,
        );
        let clock = Arc::new(context);

        Self {
            sequencer_heights,
            acks,
            nodes,
            verify,
            certificates,
            propose,
            rebroadcast,
            verify_duration: histogram::Timed::new(verify_duration, clock.clone()),
            e2e_duration: histogram::Timed::new(e2e_duration, clock),
        }
    }
}
