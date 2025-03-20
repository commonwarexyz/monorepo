use crate::authenticated::metrics;
use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::{counter::Counter, family::Family, gauge::Gauge};

/// Metrics for the [`Actor`](super::Actor)
#[derive(Default)]
pub struct Metrics {
    /// Number of tracked peers
    pub tracked_peers: Gauge,

    /// Number of reserved connections
    pub reserved_connections: Gauge,

    /// Number of rate limited connections per peer
    pub rate_limited_connections: Family<metrics::PeerLabel, Counter>,

    /// Number of peer records updated per peer
    pub updated_peers: Family<metrics::PeerLabel, Counter>,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Self::default();
        context.register(
            "tracked_peers",
            "Number of tracked peers",
            metrics.tracked_peers.clone(),
        );
        context.register(
            "reservations",
            "Number of reserved connections",
            metrics.reserved_connections.clone(),
        );
        context.register(
            "rate_limited_connections",
            "Number of rate limited connections per peer",
            metrics.rate_limited_connections.clone(),
        );
        context.register(
            "updated_peers",
            "Number of peer records updated per peer",
            metrics.updated_peers.clone(),
        );
        metrics
    }
}
