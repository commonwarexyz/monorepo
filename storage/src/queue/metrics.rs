//! Metrics for [super::Queue].

use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::gauge::Gauge;

/// Metrics for [super::Queue].
#[derive(Default)]
pub struct Metrics {
    /// Highest enqueued position (journal size).
    pub tip: Gauge,
    /// Current ack floor position.
    pub floor: Gauge,
    /// Current read position (next item to dequeue).
    pub next: Gauge,
}

impl Metrics {
    /// Create and register metrics with the given context.
    ///
    /// Metric names will be prefixed with the context's label.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let metrics = Self::default();
        context.register("tip", "Highest enqueued position", metrics.tip.clone());
        context.register("floor", "Current ack floor position", metrics.floor.clone());
        context.register(
            "next",
            "Current read position",
            metrics.next.clone(),
        );
        metrics
    }
}
