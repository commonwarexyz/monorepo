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

/// Metrics for the broadcast/linked module.
#[derive(Default)]
pub struct Metrics {
    /// Number of broadcasts received per sequencer
    pub broadcast: Family<SequencerLabel, Counter>,
    /// Number of application verifications by status
    pub verify: status::Counter,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Metrics::default();
        context.register(
            "broadcast",
            "Number of broadcasts received per sequencer",
            metrics.broadcast.clone(),
        );
        context.register(
            "verify",
            "Number of application verifications by status",
            metrics.verify.clone(),
        );
        metrics
    }
}
