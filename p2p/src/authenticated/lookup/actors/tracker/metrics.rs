use crate::authenticated::lookup::metrics;
use commonware_runtime::{Metrics as RuntimeMetrics, Registered};
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};

/// Metrics for the [super::Actor]
pub struct Metrics {
    /// The total number of unique peers in all peer sets being tracked.
    /// Does not include self, despite having a record for it.
    pub tracked: Registered<Gauge>,

    /// Blocked peers (value = expiry time as epoch millis).
    pub blocked: Registered<Family<metrics::Peer, Gauge>>,

    /// The total number of outstanding reservations.
    pub reserved: Registered<Gauge>,

    /// Unix timestamp in milliseconds when each connected peer became active.
    pub connected: Registered<Family<metrics::Peer, Gauge>>,

    /// A count of the number of rate-limited reservation events for each peer.
    pub limits: Registered<Family<metrics::Peer, Counter>>,

    /// A count of the number of updates for each peer.
    pub updates: Registered<Family<metrics::Peer, Counter>>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        Self {
            tracked: context.register(
                "tracked",
                "Total number of unique peers in all peer sets being tracked",
                Gauge::default(),
            ),
            blocked: context.register(
                "blocked",
                "Blocked peers (value = expiry time as epoch millis)",
                Family::<metrics::Peer, Gauge>::default(),
            ),
            reserved: context.register(
                "reserved",
                "Total number of outstanding reservations",
                Gauge::default(),
            ),
            connected: context.register(
                "connected",
                "Unix timestamp in milliseconds when each connected peer became active",
                Family::<metrics::Peer, Gauge>::default(),
            ),
            limits: context.register(
                "limits",
                "Count of the number of rate-limited reservation events for each peer",
                Family::<metrics::Peer, Counter>::default(),
            ),
            updates: context.register(
                "updates",
                "Count of the number of updates for each peer",
                Family::<metrics::Peer, Counter>::default(),
            ),
        }
    }
}
