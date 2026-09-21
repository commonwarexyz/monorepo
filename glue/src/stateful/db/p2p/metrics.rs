//! Metrics for the P2P resolver [`Actor`](super::Actor).

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{MetricsExt, Registered, status},
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Metrics for the QMDB P2P resolver actor.
#[derive(Clone)]
pub(super) struct Metrics {
    /// Total fetch requests dispatched to the P2P engine.
    pub fetch_requests: Registered<Counter>,

    /// Candidate deliveries by routing outcome.
    pub deliveries: status::Counter,

    /// Incoming serve requests by outcome.
    pub serve_requests: status::Counter,

    /// Whether a database is currently attached (1) or not (0).
    pub has_database: Registered<Gauge>,
}

impl Metrics {
    /// Create and register all resolver metrics.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let fetch_requests = context.register(
            "fetch_requests",
            "Total fetch requests dispatched to the P2P engine",
            Counter::default(),
        );
        let deliveries = context.family("deliveries", "Candidate deliveries by routing outcome");
        let serve_requests = context.family("serve_requests", "Incoming serve requests by outcome");
        let has_database = context.register(
            "has_database",
            "Whether a database is currently attached",
            Gauge::default(),
        );

        Self {
            fetch_requests,
            deliveries,
            serve_requests,
            has_database,
        }
    }
}
