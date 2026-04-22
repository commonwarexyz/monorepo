use commonware_cryptography::PublicKey;
use commonware_runtime::{
    metrics::{Counter, EncodeStruct, Family, Gauge},
    telemetry::metrics::status,
    Metrics as RuntimeMetrics, Registered,
};

/// Per-sequencer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Sequencer<P: PublicKey> {
    pub sequencer: P,
}

/// Metrics for the [super::Engine]
pub struct Metrics<P: PublicKey> {
    /// Number of broadcasts received by peer
    pub peer: Registered<Family<Sequencer<P>, Counter>>,
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

impl<P: PublicKey> Metrics<P> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            peer: context.family("peer", "Number of broadcasts received by peer"),
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
            waiters: context.gauge("waiters", "Number of digests being awaited"),
        }
    }
}
