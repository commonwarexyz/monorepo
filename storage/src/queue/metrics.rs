//! Metrics for [super::Queue].

use commonware_runtime::{Metrics as RuntimeMetrics, Registered};
use prometheus_client::metrics::gauge::Gauge;

/// Metrics for [super::Queue].
pub struct Metrics {
    /// Total enqueued items.
    pub tip: Registered<Gauge>,
    /// Acknowledged items.
    pub floor: Registered<Gauge>,
    /// Next item to dequeue.
    pub next: Registered<Gauge>,
}

impl Metrics {
    /// Create and register metrics with the given context.
    ///
    /// Metric names will be prefixed with the context's label.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        Self {
            tip: context.register("tip", "Total enqueued items", Gauge::default()),
            floor: context.register("floor", "Acknowledged items", Gauge::default()),
            next: context.register("next", "Next item to dequeue", Gauge::default()),
        }
    }
}
