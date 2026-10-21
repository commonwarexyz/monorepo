use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};

/// Digest cache and region fill metrics of an authenticated journal.
pub(crate) struct Metrics {
    pub resident_hits: Counter,
    pub region_hits: Counter,
    pub region_fills: Counter,
    pub filled_leaves: Counter,
    pub replayed_leaves: Counter,
    pub resident_bytes: Gauge,
}

impl Metrics {
    pub(crate) fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            resident_hits: context.counter(
                "resident_hits",
                "Requested digests served from resident memory",
            ),
            region_hits: context
                .counter("region_hits", "Requested digests served by cached regions"),
            region_fills: context.counter("region_fills", "Regions filled on demand"),
            filled_leaves: context.counter("filled_leaves", "Operations hashed to fill regions"),
            replayed_leaves: context.counter(
                "replayed_leaves",
                "Operations replayed to rebuild resident Merkle state",
            ),
            resident_bytes: context.gauge("resident_bytes", "Bytes occupied by resident digests"),
        }
    }
}
