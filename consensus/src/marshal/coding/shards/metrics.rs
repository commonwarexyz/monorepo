//! Metrics for the shard engine.

use commonware_runtime::Metrics as MetricsTrait;
use commonware_utils::{ordered::Set, Array};
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
    pub erasure_decode_duration: Histogram,
    /// Number of blocks in the reconstructed blocks cache.
    pub reconstructed_blocks_cache_count: Gauge,
    /// Number of active reconstruction states.
    pub reconstruction_states_count: Gauge,
    /// Number of shards received per peer.
    pub shards_received: Family<Peer, Counter>,
    /// Total number of blocks successfully reconstructed.
    pub blocks_reconstructed_total: Counter,
    /// Total number of block reconstruction failures.
    pub reconstruction_failures_total: Counter,
    /// Total number of stale reconstruction states pruned due to TTL expiry.
    pub stale_states_pruned_total: Counter,
}

impl ShardMetrics {
    /// Create and register metrics with the given context.
    pub fn new<P: Array>(context: &impl MetricsTrait, participants: &Set<P>) -> Self {
        let erasure_decode_duration = Histogram::new([
            3e-6, 1e-5, 3e-5, 1e-4, 3e-4, 0.001, 0.003, 0.01, 0.03, 0.1, 0.3, 1.0,
        ]);
        let reconstructed_blocks_cache_count = Gauge::default();
        let reconstruction_states_count = Gauge::default();
        let shards_received = Family::<Peer, Counter>::default();
        let blocks_reconstructed_total = Counter::default();
        let reconstruction_failures_total = Counter::default();
        let stale_states_pruned_total = Counter::default();
        context.register(
            "erasure_decode_duration",
            "Histogram of erasure decoding duration in seconds",
            erasure_decode_duration.clone(),
        );
        context.register(
            "reconstructed_blocks_cache_count",
            "Number of blocks in the reconstructed blocks cache",
            reconstructed_blocks_cache_count.clone(),
        );
        context.register(
            "reconstruction_states_count",
            "Number of active reconstruction states",
            reconstruction_states_count.clone(),
        );
        context.register(
            "shards_received",
            "Number of shards received per peer",
            shards_received.clone(),
        );
        context.register(
            "blocks_reconstructed_total",
            "Total number of blocks successfully reconstructed",
            blocks_reconstructed_total.clone(),
        );
        context.register(
            "reconstruction_failures_total",
            "Total number of block reconstruction failures",
            reconstruction_failures_total.clone(),
        );
        context.register(
            "stale_states_pruned_total",
            "Total number of stale reconstruction states pruned due to TTL expiry",
            stale_states_pruned_total.clone(),
        );

        // Pre-create counters for all participants so they appear in metrics even with zero count.
        for participant in participants.iter() {
            let _ = shards_received.get_or_create(&Peer::new(participant));
        }

        Self {
            erasure_decode_duration,
            reconstructed_blocks_cache_count,
            reconstruction_states_count,
            shards_received,
            blocks_reconstructed_total,
            reconstruction_failures_total,
            stale_states_pruned_total,
        }
    }
}
