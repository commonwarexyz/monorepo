use commonware_cryptography::PublicKey;
use commonware_runtime::{telemetry::metrics::status, Metrics as RuntimeMetrics, Registered};
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
    pub fn from<P: PublicKey>(sequencer: &P) -> Self {
        Self {
            sequencer: sequencer.to_string(),
        }
    }
}

/// Metrics for the [super::Engine]
pub struct Metrics {
    /// Number of broadcasts received by peer
    pub peer: Registered<Family<SequencerLabel, Counter>>,
    /// Number of received messages by status
    pub receive: Registered<status::Counter>,
    /// Number of `subscribe` requests by status
    pub subscribe: Registered<status::Counter>,
    /// Number of `get` requests by status
    pub get: Registered<status::Counter>,
    /// Number of digests being awaited. May be less than the number of waiters since there may be
    /// multiple waiters for the same digest.
    pub waiters: Registered<Gauge>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            peer: context.register(
                "peer",
                "Number of broadcasts received by peer",
                Family::<SequencerLabel, Counter>::default(),
            ),
            receive: context.register(
                "receive",
                "Number of received messages by status",
                status::Counter::default(),
            ),
            subscribe: context.register(
                "subscribe",
                "Number of `subscribe` requests by status",
                status::Counter::default(),
            ),
            get: context.register(
                "get",
                "Number of `get` requests by status",
                status::Counter::default(),
            ),
            waiters: context.register(
                "waiters",
                "Number of digests being awaited",
                Gauge::default(),
            ),
        }
    }
}
