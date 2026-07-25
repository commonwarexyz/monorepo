//! Metrics for the compact P2P resolver [`Actor`](super::Actor).

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{MetricsExt, status},
};

/// Metrics for the compact QMDB P2P resolver actor.
#[derive(Clone)]
pub(super) struct Metrics {
    /// Incoming serve requests by outcome.
    pub serve_requests: status::Counter,
}

impl Metrics {
    /// Create and register all compact resolver metrics.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let serve_requests = context.family("serve_requests", "Incoming serve requests by outcome");

        Self { serve_requests }
    }
}
