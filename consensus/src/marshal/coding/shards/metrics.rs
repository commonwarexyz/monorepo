//! Metrics for the shard engine.

use commonware_runtime::{
    telemetry::metrics::histogram::Buckets, Metrics as MetricsTrait, Registered,
};
use commonware_utils::Array;
use prometheus_client::{
    encoding::EncodeLabelSet,
    metrics::{counter::Counter, family::Family, gauge::Gauge, histogram::Histogram},
};

/// Label for per-peer metrics.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
pub struct Peer {
    pub peer: String,
}

impl Peer {
    pub fn new(peer: &impl Array) -> Self {
        Self {
            peer: peer.to_string(),
        }
    }
}

/// Metrics for the shard engine.
pub struct ShardMetrics {
    /// Histogram of erasure decoding duration in seconds.
    pub erasure_decode_duration: Registered<Histogram>,
    /// Number of blocks in the reconstructed blocks cache.
    pub reconstructed_blocks_cache_count: Registered<Gauge>,
    /// Number of active reconstruction states.
    pub reconstruction_states_count: Registered<Gauge>,
    /// Number of shards received per peer.
    pub shards_received: Registered<Family<Peer, Counter>>,
    /// Total number of blocks successfully reconstructed.
    pub blocks_reconstructed_total: Registered<Counter>,
    /// Total number of block reconstruction failures.
    pub reconstruction_failures_total: Registered<Counter>,
}

impl ShardMetrics {
    /// Create and register metrics with the given context.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let erasure_decode_duration = context.register(
            "erasure_decode_duration",
            "Histogram of erasure decoding duration in seconds",
            Histogram::new(Buckets::LOCAL),
        );
        let reconstructed_blocks_cache_count = context.register(
            "reconstructed_blocks_cache_count",
            "Number of blocks in the reconstructed blocks cache",
            Gauge::default(),
        );
        let reconstruction_states_count = context.register(
            "reconstruction_states_count",
            "Number of active reconstruction states",
            Gauge::default(),
        );
        let shards_received = context.register(
            "shards_received",
            "Number of shards received per peer",
            Family::<Peer, Counter>::default(),
        );
        let blocks_reconstructed_total = context.register(
            "blocks_reconstructed_total",
            "Total number of blocks successfully reconstructed",
            Counter::default(),
        );
        let reconstruction_failures_total = context.register(
            "reconstruction_failures_total",
            "Total number of block reconstruction failures",
            Counter::default(),
        );

        Self {
            erasure_decode_duration,
            reconstructed_blocks_cache_count,
            reconstruction_states_count,
            shards_received,
            blocks_reconstructed_total,
            reconstruction_failures_total,
        }
    }
}
