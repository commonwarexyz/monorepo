//! Metrics registered by the resolver actor.

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Counter, Histogram, MetricsExt as _, histogram},
};

/// Resolver actor metrics.
pub(super) struct Metrics {
    /// Machine resolution requests accepted.
    pub(crate) requests: Counter,
    /// Requests completed with a usable proof.
    pub(crate) resolved: Counter,
    /// Peer responses that failed to decode or do not resolve the requested view.
    pub(crate) mismatched: Counter,
    /// Resolved proofs the machine rejected.
    pub(crate) rejected: Counter,
    /// Peer requests served from retained proofs.
    pub(crate) served: Counter,
    /// Latency of successful resolution jobs.
    pub(crate) resolved_latency: Histogram,
}

impl Metrics {
    pub(crate) fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            requests: context.counter("requests", "machine resolution requests accepted"),
            resolved: context.counter("resolved", "requests completed with the exact object"),
            mismatched: context.counter(
                "mismatched",
                "peer responses that failed to decode or do not resolve the requested view",
            ),
            rejected: context.counter("rejected", "resolved proofs the machine rejected"),
            served: context.counter("served", "peer requests served from retained view proofs"),
            resolved_latency: context.histogram(
                "resolved_latency",
                "latency of successful resolution jobs",
                histogram::Buckets::NETWORK,
            ),
        }
    }
}
