//! Metrics for the shard engine.

use commonware_runtime::{
    metrics::{Counter, CounterFamily, EncodeLabelSet, Gauge, Histogram},
    telemetry::metrics::histogram::Buckets,
    Metrics as MetricsTrait,
    Registered,
};
use commonware_utils::Array;

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
    pub shards_received: Registered<CounterFamily<Peer>>,
    /// Total number of blocks successfully reconstructed.
    pub blocks_reconstructed_total: Registered<Counter>,
    /// Total number of block reconstruction failures.
    pub reconstruction_failures_total: Registered<Counter>,
}

impl ShardMetrics {
    /// Create and register metrics with the given context.
    pub fn new(context: &impl MetricsTrait) -> Self {
        let erasure_decode_duration = context.histogram(
            "erasure_decode_duration",
            "Histogram of erasure decoding duration in seconds",
            Buckets::LOCAL,
        );
        let reconstructed_blocks_cache_count = context.gauge(
            "reconstructed_blocks_cache_count",
            "Number of blocks in the reconstructed blocks cache",
        );
        let reconstruction_states_count = context.gauge(
            "reconstruction_states_count",
            "Number of active reconstruction states",
        );
        let shards_received = context.counter_family(
            "shards_received",
            "Number of shards received per peer",
        );
        let blocks_reconstructed_total = context.counter(
            "blocks_reconstructed_total",
            "Total number of blocks successfully reconstructed",
        );
        let reconstruction_failures_total = context.counter(
            "reconstruction_failures_total",
            "Total number of block reconstruction failures",
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
