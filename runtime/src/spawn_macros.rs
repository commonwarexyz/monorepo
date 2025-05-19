// Macros shared across runtime implementations.

#[macro_export]
macro_rules! spawn_setup {
    ($ctx:ident, future) => {{
        let label = $crate::telemetry::metrics::task::Label::future($ctx.name.clone());
        $ctx.executor
            .metrics
            .tasks_spawned
            .get_or_create(&label)
            .inc();
        let gauge = $ctx.executor
            .metrics
            .tasks_running
            .get_or_create(&label)
            .clone();
        (label, gauge)
    }};
    ($ctx:ident, blocking, $dedicated:expr) => {{
        let label = if $dedicated {
            $crate::telemetry::metrics::task::Label::blocking_dedicated($ctx.name.clone())
        } else {
            $crate::telemetry::metrics::task::Label::blocking_shared($ctx.name.clone())
        };
        $ctx.executor
            .metrics
            .tasks_spawned
            .get_or_create(&label)
            .inc();
        let gauge = $ctx.executor
            .metrics
            .tasks_running
            .get_or_create(&label)
            .clone();
        (label, gauge)
    }};
}
