use commonware_cryptography::PublicKey;
use commonware_runtime::{
    metrics::{Counter, EncodeStruct, GaugeFamily},
    telemetry::metrics::{histogram, status},
    Clock, Metrics as RuntimeMetrics,
};
use std::sync::Arc;

/// Per-sequencer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Sequencer<P: PublicKey> {
    pub sequencer: P,
}

/// Metrics for the [super::Engine]
pub struct Metrics<E: RuntimeMetrics + Clock, P: PublicKey> {
    /// Height per sequencer
    pub sequencer_heights: GaugeFamily<Sequencer<P>>,
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

impl<E: RuntimeMetrics + Clock, P: PublicKey> Metrics<E, P> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init(context: E) -> Self {
        let sequencer_heights = context.family("sequencer_heights", "Height per sequencer tracked");
        let acks = context.register(
            "acks",
            "Number of acks processed by status",
            status::Raw::default(),
        );
        let nodes = context.register(
            "nodes",
            "Number of nodes processed by status",
            status::Raw::default(),
        );
        let verify = context.register(
            "verify",
            "Number of application verifications by status",
            status::Raw::default(),
        );
        let certificates = context.counter("certificates", "Number of certificates produced");
        let propose = context.register(
            "propose",
            "Number of propose attempts by status",
            status::Raw::default(),
        );
        let rebroadcast = context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            status::Raw::default(),
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
