use commonware_runtime::{telemetry::status, Metrics as RuntimeMetrics};
use commonware_utils::Array;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family},
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

/// Metrics for the [`Engine`](super::Engine)
#[derive(Default)]
pub struct Metrics {
    /// Number of broadcasts received by peer
    pub peer: Family<SequencerLabel, Counter>,
    /// Number of received messages by status
    pub receive: status::Counter,
    /// Number of retrieves by status
    pub retrieve: status::Counter,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Metrics::default();
        context.register(
            "peer",
            "Number of broadcasts received by peer",
            metrics.peer.clone(),
        );
        context.register(
            "receive",
            "Number of received messages by status",
            metrics.receive.clone(),
        );
        context.register(
            "retrieve",
            "Number of retrieves by status",
            metrics.retrieve.clone(),
        );
        metrics
    }
}
