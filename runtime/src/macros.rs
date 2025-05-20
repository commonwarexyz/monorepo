//! Macros shared across runtime implementations.

/// Prepare metrics for a spawned task.
///
/// This macro returns a tuple `(Label, Gauge)`:
/// - `Label`: A label representing the task's metrics.
/// - `Gauge`: A gauge tracking the number of running tasks with the given label.
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

    // Increment the number of spawned tasks and return a gauge for the number of running tasks
    ($label:expr, @make $ctx:ident) => {{
        let label = $label;
        let metrics = &$ctx.executor.metrics;
        metrics.tasks_spawned.get_or_create(&label).inc();
        let gauge = metrics.tasks_running.get_or_create(&label).clone();
        (label, gauge)
    }};
}
