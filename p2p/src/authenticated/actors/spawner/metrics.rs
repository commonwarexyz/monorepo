use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::gauge::Gauge;

/// Metrics for the [`Actor`](super::Actor)
#[derive(Default)]
pub struct Metrics {
    /// Number of connected peers
    pub connections: Gauge,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Self::default();
        context.register(
            "connections",
            "Number of connected peers",
            metrics.connections.clone(),
        );
        metrics
    }
}
