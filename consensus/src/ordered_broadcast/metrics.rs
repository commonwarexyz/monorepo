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
        let sequencer_heights = context.get_or_register_default::<Family<SequencerLabel, Gauge>>(
            "sequencer_heights",
            "Height per sequencer tracked",
        );
        let acks = context.get_or_register_default::<status::Counter>(
            "acks",
            "Number of acks processed by status",
        );
        let nodes = context.get_or_register_default::<status::Counter>(
            "nodes",
            "Number of nodes processed by status",
        );
        let verify = context.get_or_register_default::<status::Counter>(
            "verify",
            "Number of application verifications by status",
        );
        let certificates = context
            .get_or_register_default::<Counter>("certificates", "Number of certificates produced");
        let propose = context.get_or_register_default::<status::Counter>(
            "propose",
            "Number of propose attempts by status",
        );
        let rebroadcast = context.get_or_register_default::<status::Counter>(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
        );
        let verify_duration = context.get_or_register_with(
            "verify_duration",
            "Histogram of application verification durations",
            || Histogram::new(histogram::Buckets::LOCAL),
        );
        let e2e_duration = context.get_or_register_with(
            "e2e_duration",
            "Histogram of time from new proposal to certificate generation",
            || Histogram::new(histogram::Buckets::NETWORK),
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
