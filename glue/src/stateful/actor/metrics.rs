//! Metrics for the stateful actor.

use commonware_runtime::{
    Metrics as MetricsTrait,
    telemetry::metrics::{GaugeExt, Registered, histogram::Timed},
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};

/// Duration buckets from 1ms to 1s, finer than [`Buckets::LOCAL`] between 10ms and 1s.
///
/// [`Buckets::LOCAL`]: commonware_runtime::telemetry::metrics::histogram::Buckets::LOCAL
const BUCKETS: [f64; 10] = [0.001, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0];

/// Metrics for the stateful actor.
#[derive(Clone)]
pub(crate) struct Metrics {
    /// Whether the actor has finished startup state sync or recovery.
    pub sync_done: Registered<Gauge>,

    /// Unfinalized blocks with cached speculative state.
    pub pending_blocks: Registered<Gauge>,

    /// Total cached states discarded by finalizations because they do not descend from the
    /// finalized block.
    pub pruned_forks: Registered<Counter>,

    /// Time taken to build a block, excluding parent recovery.
    pub propose_duration: Timed,

    /// Time taken by verifications that accept the block.
    pub verify_duration: Timed,

    /// Time taken to apply a newly finalized block.
    pub finalize_duration: Timed,

    /// Time taken to fetch and replay missing ancestors, recorded on success.
    pub rebuild_pending_duration: Timed,

    /// Time taken to fetch an ancestor for application processing.
    pub ancestor_fetch_duration: Timed,

    /// Missing ancestors walked by the most recent successful fetch and replay.
    pub rebuild_pending_depth: Registered<Gauge>,
}

impl Metrics {
    /// Creates and registers the stateful actor's metrics.
    pub fn new<E: MetricsTrait>(context: &E) -> Self {
        let sync_done = context.register(
            "sync_done",
            "Whether startup state sync or recovery is complete",
            Gauge::default(),
        );
        let _ = sync_done.try_set(0);

        let pending_blocks = context.register(
            "pending_blocks",
            "Unfinalized blocks with cached speculative state",
            Gauge::default(),
        );

        let pruned_forks = context.register(
            "pruned_forks",
            "Total cached states discarded for not descending from the finalized block",
            Counter::default(),
        );

        let propose_hist = context.register(
            "propose_duration",
            "Histogram of time taken to build a block, excluding parent recovery, in seconds",
            Histogram::new(BUCKETS),
        );

        let verify_hist = context.register(
            "verify_duration",
            "Histogram of time taken by verifications that accept the block, in seconds",
            Histogram::new(BUCKETS),
        );

        let finalize_hist = context.register(
            "finalize_duration",
            "Histogram of time taken to apply a newly finalized block, in seconds",
            Histogram::new(BUCKETS),
        );

        let rebuild_hist = context.register(
            "rebuild_pending_duration",
            "Histogram of time taken to fetch and replay missing ancestors, in seconds",
            Histogram::new(BUCKETS),
        );

        let rebuild_pending_depth = context.register(
            "rebuild_pending_depth",
            "Missing ancestors walked by the most recent successful fetch and replay",
            Gauge::default(),
        );

        let ancestor_fetch_hist = context.register(
            "ancestor_fetch_duration",
            "Histogram of time taken to fetch an ancestor for application processing, in seconds",
            Histogram::new(BUCKETS),
        );

        Self {
            sync_done,
            pending_blocks,
            pruned_forks,
            propose_duration: Timed::new(propose_hist),
            verify_duration: Timed::new(verify_hist),
            finalize_duration: Timed::new(finalize_hist),
            rebuild_pending_duration: Timed::new(rebuild_hist),
            ancestor_fetch_duration: Timed::new(ancestor_fetch_hist),
            rebuild_pending_depth,
        }
    }
}
