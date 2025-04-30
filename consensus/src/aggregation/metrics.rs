use commonware_runtime::{telemetry::metrics::status, Metrics as RuntimeMetrics};
use commonware_utils::Array;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, gauge::Gauge},
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
pub struct Metrics {
    /// Current height
    pub height: Gauge,
    /// Number of acks processed by status
    pub acks: status::Counter,
    /// Number of threshold signatures produced
    pub threshold: Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Self {
            height: Gauge::default(),
            acks: status::Counter::default(),
            threshold: Counter::default(),
            rebroadcast: status::Counter::default(),
        };
        context.register("height", "Current height", metrics.height.clone());
        context.register(
            "acks",
            "Number of acks processed by status",
            metrics.acks.clone(),
        );
        context.register(
            "threshold",
            "Number of threshold signatures produced",
            metrics.threshold.clone(),
        );
        context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            metrics.rebroadcast.clone(),
        );
        metrics
    }
}
