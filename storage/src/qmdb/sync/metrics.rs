use commonware_runtime::telemetry::metrics::{Gauge, GaugeExt, MetricsExt};

/// Progress gauges updated by a sync flow.
///
/// Progress is expressed as the synced size against the size
/// of the current sync target. The gauges match once the flow has synced the
/// latest target.
pub struct Metrics {
    /// Size of the current sync target.
    target_size: Gauge,
    /// Database size reached by sync.
    size: Gauge,
}

impl Metrics {
    /// Register sync progress metrics on the provided context.
    pub fn new(context: &impl commonware_runtime::Metrics) -> Self {
        Self {
            target_size: context.gauge("target_size", "Size of the current sync target"),
            size: context.gauge(
                "size",
                "Database size reached by sync, equal to target_size when sync completes",
            ),
        }
    }

    /// Record the size of the current sync target.
    pub fn record_target(&self, size: u64) {
        let _ = self.target_size.try_set(size);
    }

    /// Record the database size reached by sync so far.
    pub fn record_synced(&self, size: u64) {
        let _ = self.size.try_set(size);
    }
}
