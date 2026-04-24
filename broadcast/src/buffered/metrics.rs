use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{status, CounterFamily, EncodeStruct, Gauge, MetricsExt as _},
    Metrics as RuntimeMetrics,
};

/// Per-sequencer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Sequencer<P: PublicKey> {
    pub sequencer: P,
}

/// Metrics for the [super::Engine]
pub struct Metrics<P: PublicKey> {
    /// Number of broadcasts received by peer
    pub peer: CounterFamily<Sequencer<P>>,
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

impl<P: PublicKey> Metrics<P> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            peer: context.family("peer", "Number of broadcasts received by peer"),
            receive: context.family("receive", "Number of received messages by status"),
            subscribe: context.family(
                "subscribe",
                "Number of `subscribe` requests by status",
            ),
            get: context.family("get", "Number of `get` requests by status"),
            waiters: context.gauge("waiters", "Number of digests being awaited"),
        }
    }
}
