use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _},
};

/// Digest cache and reconstruction metrics of an authenticated journal.
#[derive(Clone)]
pub(crate) struct Metrics {
    pub resident_hits: Counter,
    pub region_hits: Counter,
    pub region_fills: Counter,
    pub reconstructed_leaves: Counter,
    pub reconstructed_bytes: Counter,
    pub reconstructed_parents: Counter,
    pub replayed_leaves: Counter,
    pub resident_bytes: Gauge,
    pub resident_capacity_bytes: Gauge,
    pub cached_regions: Gauge,
    pub region_capacity: Gauge,
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
            reconstructed_leaves: context.counter(
                "reconstructed_leaves",
                "Operations hashed during proof reconstruction",
            ),
            reconstructed_bytes: context.counter(
                "reconstructed_bytes",
                "Encoded operation bytes hashed during proof reconstruction",
            ),
            reconstructed_parents: context.counter(
                "reconstructed_parents",
                "Internal digests hashed during proof reconstruction",
            ),
            replayed_leaves: context.counter(
                "replayed_leaves",
                "Operations replayed to rebuild resident Merkle state",
            ),
            resident_bytes: context.gauge("resident_bytes", "Bytes occupied by resident digests"),
            resident_capacity_bytes: context.gauge(
                "resident_capacity_bytes",
                "Bytes allocated for resident digests",
            ),
            cached_regions: context.gauge("cached_regions", "Cached regions"),
            region_capacity: context.gauge("region_capacity", "Maximum number of cached regions"),
        }
    }
}
