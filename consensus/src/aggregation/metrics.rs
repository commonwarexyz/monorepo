use commonware_runtime::{telemetry::metrics::status, Metrics as RuntimeMetrics};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Metrics for the [`Engine`](super::Engine)
pub struct Metrics {
    /// Current height
    pub height: Gauge,
    /// Number of verifies processed by status
    pub verify: status::Counter,
    /// Number of [`Ack`](super::types::Ack) messages processed by status
    pub acks: status::Counter,
    /// Number of threshold signatures produced
    pub threshold: Counter,
    /// Number of rebroadcast attempts by status
    pub rebroadcast: status::Counter,
}

impl Metrics {
    /// Create and return a new set of metrics, registered with the given context.
    pub fn init<E: RuntimeMetrics>(context: E) -> Self {
        let metrics = Self {
            height: Gauge::default(),
            verify: status::Counter::default(),
            acks: status::Counter::default(),
            threshold: Counter::default(),
            rebroadcast: status::Counter::default(),
        };
        context.register("height", "Current height", metrics.height.clone());
        context.register(
            "verify",
            "Number of verifies processed by status",
            metrics.verify.clone(),
        );
        context.register(
            "acks",
            "Number of Ack messages processed by status",
            metrics.acks.clone(),
        );
        context.register(
            "threshold",
            "Number of threshold signatures produced",
            metrics.threshold.clone(),
        );
        context.register(
            "rebroadcast",
            "Number of rebroadcast attempts by status",
            metrics.rebroadcast.clone(),
        );
        metrics
    }
}
