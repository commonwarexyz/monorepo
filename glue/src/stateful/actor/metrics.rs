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

    /// Wall-clock duration of proposals that produce a block.
    pub propose_duration: Timed,

    /// Wall-clock duration of verifications that accept the block.
    pub verify_duration: Timed,

    /// Wall-clock duration of applying a newly finalized block.
    pub finalize_duration: Timed,

    /// Wall-clock duration of successfully fetching and replaying missing ancestors.
    pub rebuild_pending_duration: Timed,

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
            "Wall-clock duration of proposals that produce a block",
            Histogram::new(BUCKETS),
        );

        let verify_hist = context.register(
            "verify_duration",
            "Wall-clock duration of verifications that accept the block",
            Histogram::new(BUCKETS),
        );

        let finalize_hist = context.register(
            "finalize_duration",
            "Wall-clock duration of applying a newly finalized block",
            Histogram::new(BUCKETS),
        );

        let rebuild_hist = context.register(
            "rebuild_pending_duration",
            "Wall-clock duration of successfully fetching and replaying missing ancestors",
            Histogram::new(BUCKETS),
        );

        let rebuild_pending_depth = context.register(
            "rebuild_pending_depth",
            "Missing ancestors walked by the most recent successful fetch and replay",
            Gauge::default(),
        );

        Self {
            sync_done,
            pending_blocks,
            pruned_forks,
            propose_duration: Timed::new(propose_hist),
            verify_duration: Timed::new(verify_hist),
            finalize_duration: Timed::new(finalize_hist),
            rebuild_pending_duration: Timed::new(rebuild_hist),
            rebuild_pending_depth,
        }
    }
}
