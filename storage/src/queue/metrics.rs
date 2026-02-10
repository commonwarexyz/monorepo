//! Metrics for [super::Queue].

use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::gauge::Gauge;

/// Metrics for [super::Queue].
#[derive(Default)]
pub struct Metrics {
    /// Total enqueued items.
    pub tip: Gauge,
    /// Acknowledged items.
    pub floor: Gauge,
    /// Next item to dequeue.
    pub next: Gauge,
}

impl Metrics {
    /// Create and register metrics with the given context.
    ///
    /// Metric names will be prefixed with the context's label.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let metrics = Self::default();
        context.register("tip", "Total enqueued items", metrics.tip.clone());
        context.register("floor", "Acknowledged items", metrics.floor.clone());
        context.register("next", "Next item to dequeue", metrics.next.clone());
        metrics
    }
}
