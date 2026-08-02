use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{Counter, Histogram, MetricsExt as _, histogram},
};

pub(super) struct Metrics {
    pub requests: Counter,
    pub resolved: Counter,
    pub mismatched: Counter,
    pub served: Counter,
    pub resolved_latency: Histogram,
}

impl Metrics {
    pub fn new<E: MetricsTrait>(context: &E) -> Self {
        let requests = context.counter("requests", "machine resolution requests accepted");
        let resolved = context.counter("resolved", "requests completed with the exact object");
        let mismatched = context.counter("mismatched", "responses rejected as mismatched");
        let served = context.counter("served", "peer requests served from retained checkpoints");
        let resolved_latency = context.histogram(
            "resolved_latency",
            "latency of successful resolution jobs",
            histogram::Buckets::NETWORK,
        );

        Self {
            requests,
            resolved,
            mismatched,
            served,
            resolved_latency,
        }
    }
}
