//! Metrics for the P2P resolver [`Actor`](super::Actor).

use commonware_runtime::{telemetry::metrics::status, Metrics as MetricsTrait};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Metrics for the QMDB P2P resolver actor.
#[derive(Clone)]
pub(super) struct Metrics {
    /// Current number of in-flight fetch request keys.
    pub pending_requests: Gauge,

    /// Total fetch requests dispatched to the P2P engine.
    pub fetch_requests: Counter,

    /// Total cancelled requests.
    pub cancel_requests: Counter,

    /// Deliveries from peers by outcome.
    pub deliveries: status::Counter,

    /// Incoming serve requests by outcome.
    pub serve_requests: status::Counter,

    /// Whether a database is currently attached (1) or not (0).
    pub has_database: Gauge,
}

impl Metrics {
    /// Create and register all resolver metrics.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let pending_requests = Gauge::default();
        context.register(
            "pending_requests",
            "Current in-flight fetch request keys",
            pending_requests.clone(),
        );

        let fetch_requests = Counter::default();
        context.register(
            "fetch_requests",
            "Total fetch requests dispatched to the P2P engine",
            fetch_requests.clone(),
        );

        let cancel_requests = Counter::default();
        context.register(
            "cancel_requests",
            "Total cancelled requests",
            cancel_requests.clone(),
        );

        let deliveries = status::Counter::default();
        context.register(
            "deliveries",
            "Deliveries from peers by outcome",
            deliveries.clone(),
        );

        let serve_requests = status::Counter::default();
        context.register(
            "serve_requests",
            "Incoming serve requests by outcome",
            serve_requests.clone(),
        );

        let has_database = Gauge::default();
        context.register(
            "has_database",
            "Whether a database is currently attached",
            has_database.clone(),
        );

        Self {
            pending_requests,
            fetch_requests,
            cancel_requests,
            deliveries,
            serve_requests,
            has_database,
        }
    }
}
