use crate::authenticated::lookup::metrics;
use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{CounterFamily, Gauge, GaugeFamily, MetricsExt as _},
    Metrics as RuntimeMetrics,
};

/// Metrics for the [super::Actor]
pub struct Metrics<P: PublicKey> {
    /// The total number of unique peers in all peer sets being tracked.
    /// Does not include self, despite having a record for it.
    pub tracked: Gauge,

    /// Blocked peers (value = expiry time as epoch millis).
    pub blocked: GaugeFamily<metrics::Peer<P>>,

    /// The total number of outstanding reservations.
    pub reserved: Gauge,

    /// Unix timestamp in milliseconds when each connected peer became active.
    pub connected: GaugeFamily<metrics::Peer<P>>,

    /// A count of the number of rate-limited reservation events for each peer.
    pub limits: CounterFamily<metrics::Peer<P>>,

    /// A count of the number of updates for each peer.
    pub updates: CounterFamily<metrics::Peer<P>>,
}

impl<P: PublicKey> Metrics<P> {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            tracked: context.gauge(
                "tracked",
                "Total number of unique peers in all peer sets being tracked",
            ),
            blocked: context.family(
                "blocked",
                "Blocked peers (value = expiry time as epoch millis)",
            ),
            reserved: context.gauge("reserved", "Total number of outstanding reservations"),
            connected: context.family(
                "connected",
                "Unix timestamp in milliseconds when each connected peer became active",
            ),
            limits: context.family(
                "limits",
                "Count of the number of rate-limited reservation events for each peer",
            ),
            updates: context.family("updates", "Count of the number of updates for each peer"),
        }
    }
}
