//! Counts of the runtime's tasks in a context's encoded metrics.

use commonware_runtime::telemetry::metrics::metric_samples;

/// The runtime's gauge of running tasks.
pub(crate) const RUNNING: &str = "runtime_tasks_running";

/// The runtime's counter of spawned tasks.
pub(crate) const SPAWNED: &str = "runtime_tasks_spawned_total";

/// The sum of the runtime's `metric` samples for tasks whose labels contain `label`.
pub(crate) fn tasks(metrics: &str, metric: &str, label: &str) -> u64 {
    metric_samples(metrics, metric)
        .filter(|(labels, _)| labels.contains(label))
        .filter_map(|(_, value)| value.parse::<u64>().ok())
        .sum()
}
