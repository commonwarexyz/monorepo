use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
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
    pub verify_duration: histogram::Timed<E>,
    /// Histogram of time from new proposal to certificate generation
    pub e2e_duration: histogram::Timed<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let sequencer_heights = Family::default();
        context.register(
            "sequencer_heights",
            "Height per sequencer tracked",
            sequencer_heights.clone(),
        );
        let acks = status::Counter::default();
        context.register("acks", "Number of acks processed by status", acks.clone());
        let nodes = status::Counter::default();
        context.register(
            "nodes",
            "Number of nodes processed by status",
            nodes.clone(),
        );
        let verify = status::Counter::default();
        context.register(
            "verify",
            "Number of application verifications by status",
            verify.clone(),
        );
        let certificates = Counter::default();
        context.register(
            "certificates",
            "Number of certificates produced",
            certificates.clone(),
        );
        let propose = status::Counter::default();
        context.register(
            "propose",
            "Number of propose attempts by status",
            propose.clone(),
        );
        let rebroadcast = status::Counter::default();
        context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            rebroadcast.clone(),
        );
        let verify_duration = Histogram::new(histogram::Buckets::LOCAL);
        context.register(
            "verify_duration",
            "Histogram of application verification durations",
            verify_duration.clone(),
        );
        let e2e_duration = Histogram::new(histogram::Buckets::NETWORK);
        context.register(
            "e2e_duration",
            "Histogram of time from new proposal to certificate generation",
            e2e_duration.clone(),
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
