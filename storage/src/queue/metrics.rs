//! Metrics for [super::Queue].

use commonware_runtime::{metrics::Gauge, Metrics as RuntimeMetrics};

/// Metrics for [super::Queue].
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
        Self {
            tip: context.gauge("tip", "Total enqueued items"),
            floor: context.gauge("floor", "Acknowledged items"),
            next: context.gauge("next", "Next item to dequeue"),
        }
    }
}
