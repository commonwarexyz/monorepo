use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge},
    registry::Registry,
};

#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub(super) struct Work {
    pub(super) label: String,
}

#[derive(Debug)]
pub(super) struct Metrics {
    pub(super) tasks_spawned: Family<Work, Counter>,
    pub(super) tasks_running: Family<Work, Gauge>,
    pub(super) blocking_tasks_spawned: Family<Work, Counter>,
    pub(super) blocking_tasks_running: Family<Work, Gauge>,

    // As nice as it would be to track each of these by socket address,
    // it quickly becomes an OOM attack vector.
    pub(super) inbound_connections: Counter,
    pub(super) outbound_connections: Counter,
    pub(super) inbound_bandwidth: Counter,
    pub(super) outbound_bandwidth: Counter,
}

impl Metrics {
    pub(super) fn init(registry: &mut Registry) -> Self {
        let metrics = Self {
            tasks_spawned: Family::default(),
            tasks_running: Family::default(),
            blocking_tasks_spawned: Family::default(),
            blocking_tasks_running: Family::default(),
            inbound_connections: Counter::default(),
            outbound_connections: Counter::default(),
            inbound_bandwidth: Counter::default(),
            outbound_bandwidth: Counter::default(),
        };
        registry.register(
            "tasks_spawned",
            "Total number of tasks spawned",
            metrics.tasks_spawned.clone(),
        );
        registry.register(
            "tasks_running",
            "Number of tasks currently running",
            metrics.tasks_running.clone(),
        );
        registry.register(
            "blocking_tasks_spawned",
            "Total number of blocking tasks spawned",
            metrics.blocking_tasks_spawned.clone(),
        );
        registry.register(
            "blocking_tasks_running",
            "Number of blocking tasks currently running",
            metrics.blocking_tasks_running.clone(),
        );
        registry.register(
            "inbound_connections",
            "Number of connections created by dialing us",
            metrics.inbound_connections.clone(),
        );
        registry.register(
            "outbound_connections",
            "Number of connections created by dialing others",
            metrics.outbound_connections.clone(),
        );
        registry.register(
            "inbound_bandwidth",
            "Bandwidth used by receiving data from others",
            metrics.inbound_bandwidth.clone(),
        );
        registry.register(
            "outbound_bandwidth",
            "Bandwidth used by sending data to others",
            metrics.outbound_bandwidth.clone(),
        );
        metrics
    }
}
