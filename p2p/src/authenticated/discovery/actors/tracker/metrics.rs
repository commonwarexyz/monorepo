use crate::authenticated::discovery::metrics;
use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};

/// Metrics for the [super::Actor]
#[derive(Default)]
pub struct Metrics {
    /// The total number of unique peers in all peer sets being tracked.
    /// Includes bootstrappers, even if they are not in any peer set.
    /// Does not include self, despite having a record for it.
    pub tracked: Gauge,

    /// The total number of blocked peers.
    pub blocked: Gauge,

    /// The total number of outstanding reservations.
    pub reserved: Gauge,

    /// A count of the number of rate-limited connection events for each peer.
    pub limits: Family<metrics::Peer, Counter>,

    /// A count of the number of updates for each peer.
    pub updates: Family<metrics::Peer, Counter>,

    /// Number of times a peer was rejected because they were blocked.
    pub rejected_blocked: Counter,

    /// Number of times a peer was rejected because they were unregistered.
    pub rejected_unregistered: Counter,

    /// Number of times a peer was rejected because they were already connected.
    pub rejected_reserved: Counter,

    /// Number of times a peer was rejected because they are ourselves.
    pub rejected_myself: Counter,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Self::default();
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
        context.register(
            "rejected_blocked",
            "Number of times a peer was rejected because they were blocked",
            metrics.rejected_blocked.clone(),
        );
        context.register(
            "rejected_unregistered",
            "Number of times a peer was rejected because they were unregistered",
            metrics.rejected_unregistered.clone(),
        );
        context.register(
            "rejected_reserved",
            "Number of times a peer was rejected because they were already connected",
            metrics.rejected_reserved.clone(),
        );
        context.register(
            "rejected_myself",
            "Number of times a peer was rejected because they are ourselves",
            metrics.rejected_myself.clone(),
        );
        metrics
    }
}
