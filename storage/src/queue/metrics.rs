//! Metrics for [super::Queue].

use commonware_runtime::Metrics as RuntimeMetrics;
use prometheus_client::metrics::gauge::Gauge;

/// Metrics for [super::Queue].
#[derive(Default)]
pub struct Metrics {
    /// Total number of items enqueued (monotonic position counter).
    pub size: Gauge,

    /// Current ack floor position.
    ///
    /// All items below this position are considered acknowledged.
    pub ack_floor: Gauge,

    /// Number of out-of-order ack ranges currently tracked.
    ///
    /// High values indicate many sparse acknowledgments, which increases memory usage.
    pub acked_above_ranges: Gauge,
}

impl Metrics {
    /// Create and register metrics with the given context.
    ///
    /// Metric names will be prefixed with the context's label.
    pub fn init<E: RuntimeMetrics>(context: &E) -> Self {
        let metrics = Self::default();
        context.register("size", "Total items enqueued", metrics.size.clone());
        context.register(
            "ack_floor",
            "Current ack floor position",
            metrics.ack_floor.clone(),
        );
        context.register(
            "acked_above_ranges",
            "Out-of-order ack ranges tracked",
            metrics.acked_above_ranges.clone(),
        );
        metrics
    }
}
