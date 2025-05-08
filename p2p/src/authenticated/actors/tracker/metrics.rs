use crate::authenticated::metrics;
use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};

/// Metrics for the [`Actor`](super::Actor)
#[derive(Default)]
pub struct Metrics {
    /// The total number of unique peers in all peer sets being tracked.
    pub tracked: Gauge,

    /// The total number of blocked peers.
    pub blocked: Gauge,

    /// The total number of outstanding reservations.
    pub reserved: Gauge,

    /// A count of the number of rate-limited connection events for each peer.
    pub limits: Family<metrics::Peer, Counter>,

    /// A count of the number of updates for each peer.
    pub updates: Family<metrics::Peer, Counter>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Metrics::default();
        context.register(
            "tracked",
            "Total number of unique peers in all peer sets being tracked",
            metrics.tracked.clone(),
        );
        context.register(
            "blocked",
            "Total number of blocked peers",
            metrics.blocked.clone(),
        );
        context.register(
            "reserved",
            "Total number of outstanding reservations",
            metrics.reserved.clone(),
        );
        context.register(
            "limits",
            "Count of the number of rate-limited connection events for each peer",
            metrics.limits.clone(),
        );
        context.register(
            "updates",
            "Count of the number of updates for each peer",
            metrics.updates.clone(),
        );
        metrics
    }
}
