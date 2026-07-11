//! Metrics for the shard engine.

use commonware_cryptography::PublicKey;
use commonware_runtime::{
    telemetry::metrics::{
        histogram::Buckets, Counter, CounterFamily, EncodeStruct, Gauge, Histogram, MetricsExt as _,
    },
    Metrics as MetricsTrait,
};

/// Per-peer label.
#[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeStruct)]
pub struct Peer<P: PublicKey> {
    pub peer: P,
}

/// Metrics for the shard engine.
pub struct ShardMetrics<P: PublicKey> {
    /// Histogram of erasure decoding duration in seconds.
    pub erasure_decode_duration: Histogram,
    /// Number of blocks in the reconstructed blocks cache.
    pub reconstructed_blocks_cache_count: Gauge,
    /// Number of active reconstruction states.
    pub reconstruction_states_count: Gauge,
    /// Number of shards received per peer.
    pub shards_received: CounterFamily<Peer<P>>,
    /// Total number of blocks successfully reconstructed.
    pub blocks_reconstructed_total: Counter,
    /// Total number of block reconstruction failures.
    pub reconstruction_failures_total: Counter,
    /// Total number of extra shards forwarded to a predicted future leader.
    pub shards_forwarded_total: Counter,
    /// Total number of leader-sent foreign-index shards dropped because the
    /// local router did not recognize their round.
    ///
    /// With a total router (one that resolves every round, like a fixed
    /// round-robin elector), this should never increment: a nonzero value
    /// indicates a router bug, a router rollout skew, or a Byzantine probe.
    pub forwarded_shards_unrouted_total: Counter,
}

impl<P: PublicKey> ShardMetrics<P> {
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
        let shards_received =
            context.family("shards_received", "Number of shards received per peer");
        let blocks_reconstructed_total = context.counter(
            "blocks_reconstructed_total",
            "Total number of blocks successfully reconstructed",
        );
        let reconstruction_failures_total = context.counter(
            "reconstruction_failures_total",
            "Total number of block reconstruction failures",
        );
        let shards_forwarded_total = context.counter(
            "shards_forwarded_total",
            "Total number of extra shards forwarded to a predicted future leader",
        );
        let forwarded_shards_unrouted_total = context.counter(
            "forwarded_shards_unrouted_total",
            "Total number of leader-sent foreign-index shards dropped for unrecognized rounds",
        );

        Self {
            erasure_decode_duration,
            reconstructed_blocks_cache_count,
            reconstruction_states_count,
            shards_received,
            blocks_reconstructed_total,
            reconstruction_failures_total,
            shards_forwarded_total,
            forwarded_shards_unrouted_total,
        }
    }
}
