//! Metrics for the P2P resolver [`Actor`](super::Actor).

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{MetricsExt, Registered, status},
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Metrics for the QMDB P2P resolver actor.
#[derive(Clone)]
pub(super) struct Metrics {
    /// Current number of in-flight fetch request keys.
    pub pending_requests: Registered<Gauge>,

    /// Total fetch requests dispatched to the P2P engine.
    pub fetch_requests: Registered<Counter>,

    /// Total cancelled requests.
    pub cancel_requests: Registered<Counter>,

    /// Deliveries from peers by outcome.
    pub deliveries: status::Counter,

    /// Incoming serve requests by outcome.
    pub serve_requests: status::Counter,

    /// Serves abandoned because the requester or the runtime went away mid-read.
    pub serve_cancelled: Registered<Counter>,

    /// Whether a serving source is currently attached (1) or not (0).
    pub has_source: Registered<Gauge>,
}

impl Metrics {
    /// Create and register all resolver metrics.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let pending_requests = context.register(
            "pending_requests",
            "Current in-flight fetch request keys",
            Gauge::default(),
        );
        let fetch_requests = context.register(
            "fetch_requests",
            "Total fetch requests dispatched to the P2P engine",
            Counter::default(),
        );
        let cancel_requests = context.register(
            "cancel_requests",
            "Total cancelled requests",
            Counter::default(),
        );
        let deliveries = context.family("deliveries", "Deliveries from peers by outcome");
        let serve_requests = context.family("serve_requests", "Incoming serve requests by outcome");
        let serve_cancelled = context.register(
            "serve_cancelled",
            "Serves abandoned because the requester or the runtime went away",
            Counter::default(),
        );
        let has_source = context.register(
            "has_source",
            "Whether a serving source is currently attached",
            Gauge::default(),
        );

        Self {
            pending_requests,
            fetch_requests,
            cancel_requests,
            deliveries,
            serve_requests,
            serve_cancelled,
            has_source,
        }
    }
}
