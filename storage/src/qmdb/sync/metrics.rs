use commonware_runtime::telemetry::metrics::{Gauge, GaugeExt, MetricsExt};

/// Progress gauges updated by a sync flow.
///
/// Progress is expressed as the number of leaves synced against the total
/// leaves in the current sync target. The gauges match once the flow has
/// synced the latest target.
pub struct Metrics {
    /// Total leaves in the current sync target.
    target_leaf_count: Gauge,
    /// Leaves synced so far.
    leaf_count: Gauge,
}

impl Metrics {
    /// Register sync progress metrics on the provided context.
    pub fn new(context: &impl commonware_runtime::Metrics) -> Self {
        Self {
            target_leaf_count: context.gauge(
                "target_leaf_count",
                "Total leaves in the current sync target",
            ),
            leaf_count: context.gauge(
                "leaf_count",
                "Leaves synced so far, equal to target_leaf_count when sync completes",
            ),
        }
    }

    /// Record the leaf count of the current sync target.
    pub fn record_target(&self, leaf_count: u64) {
        let _ = self.target_leaf_count.try_set(leaf_count);
    }

    /// Record the number of leaves synced so far.
    pub fn record_synced(&self, leaf_count: u64) {
        let _ = self.leaf_count.try_set(leaf_count);
    }
}
