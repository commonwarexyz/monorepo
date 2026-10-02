use commonware_runtime::{
    Metrics as RuntimeMetrics,
    telemetry::metrics::{Counter, Gauge, MetricsExt as _, Registered, Registration, raw},
};

#[derive(Clone)]
pub(super) struct Metrics {
    pub resident_hits: Counter,
    pub lower_hits: Counter,
    pub region_fills: Counter,
    pub reconstructed_leaves: Counter,
    pub reconstructed_bytes: Counter,
    pub reconstructed_parents: Counter,
    pub replayed_leaves: Counter,
    pub upper_payload_bytes: Gauge,
    pub upper_capacity_bytes: Gauge,
    pub cached_regions: Gauge,
    pub cache_capacity: Gauge,
}

impl Metrics {
    pub(super) fn new(context: &impl RuntimeMetrics) -> Self {
        Self {
            resident_hits: context.counter(
                "resident_hits",
                "Requested digests served from resident memory",
            ),
            lower_hits: context.counter(
                "lower_hits",
                "Requested digests served by complete lower-cache hits",
            ),
            region_fills: context.counter("region_fills", "Lower regions filled on demand"),
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
            upper_payload_bytes: context.gauge(
                "upper_payload_bytes",
                "Bytes occupied by resident upper digests",
            ),
            upper_capacity_bytes: context.gauge(
                "upper_capacity_bytes",
                "Bytes allocated for resident upper digests",
            ),
            cached_regions: context.gauge("cached_regions", "Live lower-cache regions"),
            cache_capacity: context
                .gauge("cache_capacity", "Maximum number of cached lower regions"),
        }
    }
}

impl Default for Metrics {
    fn default() -> Self {
        let counter =
            || Registered::with_registration(raw::Counter::default(), Registration::from(()));
        let gauge = || Registered::with_registration(raw::Gauge::default(), Registration::from(()));
        Self {
            resident_hits: counter(),
            lower_hits: counter(),
            region_fills: counter(),
            reconstructed_leaves: counter(),
            reconstructed_bytes: counter(),
            reconstructed_parents: counter(),
            replayed_leaves: counter(),
            upper_payload_bytes: gauge(),
            upper_capacity_bytes: gauge(),
            cached_regions: gauge(),
            cache_capacity: gauge(),
        }
    }
}
