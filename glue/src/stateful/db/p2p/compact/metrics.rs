//! Metrics for the compact P2P resolver [`Actor`](super::Actor).

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{MetricsExt, Registered, status},
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge};

/// Metrics for the compact QMDB P2P resolver actor.
#[derive(Clone)]
pub(super) struct Metrics {
    /// Incoming serve requests by outcome.
    pub serve_requests: status::Counter,

    /// Serves aborted because the requester stopped waiting or the actor shut down.
    pub serve_cancelled: Registered<Counter>,

    /// Whether a serving source is attached (1) or not (0).
    pub has_source: Registered<Gauge>,
}

impl Metrics {
    /// Create and register all compact resolver metrics.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let serve_requests = context.family("serve_requests", "Incoming serve requests by outcome");
        let serve_cancelled = context.register(
            "serve_cancelled",
            "Serves aborted because the requester stopped waiting or the actor shut down",
            Counter::default(),
        );
        let has_source = context.register(
            "has_source",
            "Whether a serving source is attached",
            Gauge::default(),
        );

        Self {
            serve_requests,
            serve_cancelled,
            has_source,
        }
    }
}
