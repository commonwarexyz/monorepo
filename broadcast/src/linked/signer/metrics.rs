use commonware_utils::{metrics::status, Array};
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
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
#[derive(Default, Debug)]
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
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given registry.
    pub fn init<M: commonware_runtime::Metrics>(registry: M) -> Self {
        let metrics = Self::default();
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
        metrics
    }
}
