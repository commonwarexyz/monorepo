// Macros shared across runtime implementations.

#[macro_export]
macro_rules! spawn_setup {
    ($ctx:ident, $label:expr) => {{
        $ctx.executor
            .metrics
            .tasks_spawned
            .get_or_create(&$label)
            .inc();
        $ctx.executor
            .metrics
            .tasks_running
            .get_or_create(&$label)
            .clone()
    }};
}
