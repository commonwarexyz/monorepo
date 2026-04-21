use crate::authenticated::lookup::metrics;
use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};

/// Metrics for the [super::Actor]
pub struct Metrics {
    /// The total number of unique peers in all peer sets being tracked.
    /// Does not include self, despite having a record for it.
    pub tracked: Gauge,

    /// Blocked peers (value = expiry time as epoch millis).
    pub blocked: Family<metrics::Peer, Gauge>,

    /// The total number of outstanding reservations.
    pub reserved: Gauge,

    /// Unix timestamp in milliseconds when each connected peer became active.
    pub connected: Family<metrics::Peer, Gauge>,

    /// A count of the number of rate-limited reservation events for each peer.
    pub limits: Family<metrics::Peer, Counter>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        Self {
            tracked: context.register(
                "tracked",
                "Total number of unique peers in all peer sets being tracked",
                Gauge::default(),
            ),
            blocked: context.register(
                "blocked",
                "Blocked peers (value = expiry time as epoch millis)",
                Family::default(),
            ),
            reserved: context.register(
                "reserved",
                "Total number of outstanding reservations",
                Gauge::default(),
            ),
            connected: context.register(
                "connected",
                "Unix timestamp in milliseconds when each connected peer became active",
                Family::default(),
            ),
            limits: context.register(
                "limits",
                "Count of the number of rate-limited reservation events for each peer",
                Family::default(),
            ),
        }
    }
}
