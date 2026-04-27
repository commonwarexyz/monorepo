//! Metrics for the [`Processor`](super::processor::Processor).

use commonware_runtime::{
    telemetry::metrics::{histogram::Timed, Registered},
    Clock, Metrics as MetricsTrait,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
use std::sync::Arc;

/// Buckets for histograms.
///
/// These buckets are much less coarse than [`Buckets::LOCAL`].
///
/// [`Buckets::LOCAL`]: commonware_runtime::telemetry::metrics::histogram::Buckets::LOCAL
const BUCKETS: [f64; 10] = [0.001, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0];

/// Metrics for the stateful processor.
///
/// All duration histograms use [`Timed`] wrappers for automatic recording via
/// [`Timer`](commonware_runtime::telemetry::metrics::histogram::Timer).
#[derive(Clone)]
pub(crate) struct Metrics<E: Clock> {
    /// Current number of entries in the in-memory pending map.
    pub pending_blocks: Registered<Gauge>,

    /// Total pending entries pruned after finalizations.
    pub pruned_forks: Registered<Counter>,

    /// Wall-clock duration of a full propose cycle.
    pub propose_duration: Timed<E>,

    /// Wall-clock duration of a full verify cycle.
    pub verify_duration: Timed<E>,

    /// Wall-clock duration of a finalization.
    pub finalize_duration: Timed<E>,

    /// Wall-clock duration of lazy-recovery replays via `rebuild_pending`.
    pub rebuild_pending_duration: Timed<E>,

    /// Number of blocks replayed during the most recent `rebuild_pending` call.
    pub rebuild_pending_depth: Registered<Gauge>,
}

impl<E: MetricsTrait + Clock> Metrics<E> {
    /// Create and register all processor metrics.
    ///
    /// The provided `context` is cloned internally to avoid further nesting the
    /// label hierarchy.
    pub fn new(context: E) -> Self {
        let pending_blocks = context.register(
            "pending_blocks",
            "Current entries in the in-memory pending map",
            Gauge::default(),
        );

        let pruned_forks = context.register(
            "pruned_forks",
            "Total pending entries pruned after finalizations",
            Counter::default(),
        );

        let propose_hist = context.register(
            "propose_duration",
            "Wall-clock duration of a full propose cycle",
            Histogram::new(BUCKETS),
        );

        let verify_hist = context.register(
            "verify_duration",
            "Wall-clock duration of a full verify cycle",
            Histogram::new(BUCKETS),
        );

        let finalize_hist = context.register(
            "finalize_duration",
            "Wall-clock duration of a finalization",
            Histogram::new(BUCKETS),
        );

        let rebuild_hist = context.register(
            "rebuild_pending_duration",
            "Wall-clock duration of lazy-recovery replays",
            Histogram::new(BUCKETS),
        );

        let rebuild_pending_depth = context.register(
            "rebuild_pending_depth",
            "Blocks replayed during the most recent rebuild_pending",
            Gauge::default(),
        );

        let clock = Arc::new(context);
        Self {
            pending_blocks,
            pruned_forks,
            propose_duration: Timed::new(propose_hist, clock.clone()),
            verify_duration: Timed::new(verify_hist, clock.clone()),
            finalize_duration: Timed::new(finalize_hist, clock.clone()),
            rebuild_pending_duration: Timed::new(rebuild_hist, clock),
            rebuild_pending_depth,
        }
    }
}
