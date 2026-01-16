use commonware_cryptography::PublicKey;
use commonware_runtime::{telemetry::metrics::status, Metrics as RuntimeMetrics};
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
#[derive(Default)]
pub struct Metrics {
    /// Number of broadcasts received by peer
    pub peer: Family<SequencerLabel, Counter>,
    /// Number of received messages by status
    pub receive: status::Counter,
    /// Number of `subscribe` requests by status
    pub subscribe: status::Counter,
    /// Number of `get` requests by status
    pub get: status::Counter,
    /// Number of digests being awaited. May be less than the number of waiters since there may be
    /// multiple waiters for the same digest.
    pub waiters: Gauge,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            peer: context.get_or_register_default::<Family<SequencerLabel, Counter>>(
                "peer",
                "Number of broadcasts received by peer",
            ),
            receive: context.get_or_register_default::<status::Counter>(
                "receive",
                "Number of received messages by status",
            ),
            subscribe: context.get_or_register_default::<status::Counter>(
                "subscribe",
                "Number of `subscribe` requests by status",
            ),
            get: context.get_or_register_default::<status::Counter>(
                "get",
                "Number of `get` requests by status",
            ),
            waiters: context
                .get_or_register_default::<Gauge>("waiters", "Number of digests being awaited"),
        }
    }
}
