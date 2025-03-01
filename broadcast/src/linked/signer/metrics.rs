use commonware_runtime::metrics::status;
use commonware_utils::Array;
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
    pub fn from<A: Array>(sequencer: &A) -> Self {
        Self {
            sequencer: sequencer.to_string(),
        }
    }
}

/// Metrics for the broadcast/linked module.
#[derive(Debug)]
pub struct Metrics {
    /// Height per sequencer
    pub sequencer_heights: Family<SequencerLabel, Gauge>,
    /// Number of acks processed by status
    pub acks: status::Counter,
    /// Number of nodes processed by status
    pub nodes: status::Counter,
    /// Number of application verifications by status
    pub verify: status::Counter,
    /// Number of threshold signatures produced
    pub threshold: Counter,
    /// Number of new broadcast attempts by status
    pub new_broadcast: status::Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
    /// Histogram of application verification durations
    pub verify_duration: Histogram,
    /// Histogram of time from new broadcast to threshold signature generation
    pub e2e_duration: Histogram,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given registry.
    pub fn init<M: commonware_runtime::Metrics>(registry: M) -> Self {
        let metrics = Self {
            sequencer_heights: Family::default(),
            acks: status::Counter::default(),
            nodes: status::Counter::default(),
            verify: status::Counter::default(),
            threshold: Counter::default(),
            new_broadcast: status::Counter::default(),
            rebroadcast: status::Counter::default(),
            verify_duration: Histogram::new(
                commonware_runtime::metrics::histogram::Buckets::LOCAL.into_iter(),
            ),
            e2e_duration: Histogram::new(
                commonware_runtime::metrics::histogram::Buckets::NETWORK.into_iter(),
            ),
        };
        registry.register(
            "sequencer_heights",
            "Height per sequencer tracked",
            metrics.sequencer_heights.clone(),
        );
        registry.register(
            "acks",
            "Number of acks processed by status",
            metrics.acks.clone(),
        );
        registry.register(
            "nodes",
            "Number of nodes processed by status",
            metrics.nodes.clone(),
        );
        registry.register(
            "verify",
            "Number of application verifications by status",
            metrics.verify.clone(),
        );
        registry.register(
            "threshold",
            "Number of threshold signatures produced",
            metrics.threshold.clone(),
        );
        registry.register(
            "new_broadcast",
            "Number of new broadcast attempts by status",
            metrics.new_broadcast.clone(),
        );
        registry.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            metrics.rebroadcast.clone(),
        );
        registry.register(
            "verify_duration",
            "Histogram of application verification durations",
            metrics.verify_duration.clone(),
        );
        registry.register(
            "e2e_duration",
            "Histogram of time from broadcast to threshold signature generation",
            metrics.e2e_duration.clone(),
        );
        metrics
    }
}
