//! Macros shared across runtime implementations.

/// Prepare metrics for a spawned task.
///
/// Returns a `(Label, MetricHandle)` pair for tracking spawned tasks.
///
/// The `Label` identifies the task in the metrics registry and the
/// `MetricHandle` immediately increments the `tasks_running` gauge for that
/// label. Call `MetricHandle::finish` once the task completes to decrement the
/// gauge.
#[macro_export]
macro_rules! spawn_metrics {
    // Handle future tasks
    ($ctx:ident, future) => {
        $crate::spawn_metrics!(
            $crate::telemetry::metrics::task::Label::future($ctx.name.clone()),
            @make $ctx
        )
    };

    // Handle blocking tasks
    ($ctx:ident, blocking, $dedicated:expr) => {
        $crate::spawn_metrics!(
            if $dedicated {
                $crate::telemetry::metrics::task::Label::blocking_dedicated($ctx.name.clone())
            } else {
                $crate::telemetry::metrics::task::Label::blocking_shared($ctx.name.clone())
            },
            @make $ctx
        )
    };

    // Increment the number of spawned tasks and return a metrics tracker that
    // keeps the running tasks gauge accurate
    ($label:expr, @make $ctx:ident) => {{
        let label = $label;
        let metrics = $ctx.metrics();
        metrics.tasks_spawned.get_or_create(&label).inc();
        let metric = $crate::utils::MetricHandle::new(
            metrics.tasks_running.get_or_create(&label).clone(),
        );
        (label, metric)
    }};
}
