//! Metrics registered by the resolver actor.

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Counter, Histogram, MetricsExt as _, histogram},
};

/// Resolver actor metrics.
pub(super) struct Metrics {
    /// Machine resolution requests accepted.
    pub(crate) requests: Counter,
    /// Requests completed with an artifact that provides the requested key.
    pub(crate) resolved: Counter,
    /// Peer responses that failed to decode or do not provide the requested key.
    pub(crate) mismatched: Counter,
    /// Resolved artifacts the machine rejected.
    pub(crate) rejected: Counter,
    /// Peer requests served from retained artifacts.
    pub(crate) served: Counter,
    /// Encoded bytes of the artifacts served to peer requests; the engine resolver's egress.
    pub(crate) served_bytes: Counter,
    /// Latency of successful resolution jobs.
    pub(crate) resolved_latency: Histogram,
}

impl Metrics {
    pub(crate) fn new<E: MetricsTrait>(context: &E) -> Self {
        Self {
            requests: context.counter("requests", "machine resolution requests accepted"),
            resolved: context.counter(
                "resolved",
                "requests completed with an artifact that provides the requested key",
            ),
            mismatched: context.counter(
                "mismatched",
                "peer responses that failed to decode or do not provide the requested key",
            ),
            rejected: context.counter("rejected", "resolved artifacts the machine rejected"),
            served: context.counter("served", "peer requests served from retained artifacts"),
            served_bytes: context.counter(
                "served_bytes",
                "encoded bytes of the artifacts served to peer requests",
            ),
            resolved_latency: context.histogram(
                "resolved_latency",
                "latency of successful resolution jobs",
                histogram::Buckets::NETWORK,
            ),
        }
    }
}
