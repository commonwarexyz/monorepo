//! Metrics for the [`Processor`](super::processor::Processor).

use commonware_runtime::{telemetry::metrics::histogram::Timed, Clock, Metrics as MetricsTrait};
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
    pub pending_blocks: Gauge,

    /// Total pending entries pruned after finalizations.
    pub pruned_forks: Counter,

    /// Wall-clock duration of a full propose cycle.
    pub propose_duration: Timed<E>,

    /// Wall-clock duration of a full verify cycle.
    pub verify_duration: Timed<E>,

    /// Wall-clock duration of a finalization.
    pub finalize_duration: Timed<E>,

    /// Wall-clock duration of lazy-recovery replays via `rebuild_pending`.
    pub rebuild_pending_duration: Timed<E>,

    /// Number of blocks replayed during the most recent `rebuild_pending` call.
    pub rebuild_pending_depth: Gauge,
}

impl<E: MetricsTrait + Clock> Metrics<E> {
    /// Create and register all processor metrics.
    ///
    /// The provided `context` is cloned internally to avoid further nesting the
    /// label hierarchy.
    pub fn new(context: E) -> Self {
        let pending_blocks = Gauge::default();
        context.register(
            "pending_blocks",
            "Current entries in the in-memory pending map",
            pending_blocks.clone(),
        );

        let pruned_forks = Counter::default();
        context.register(
            "pruned_forks",
            "Total pending entries pruned after finalizations",
            pruned_forks.clone(),
        );

        let propose_hist = Histogram::new(BUCKETS);
        context.register(
            "propose_duration",
            "Wall-clock duration of a full propose cycle",
            propose_hist.clone(),
        );

        let verify_hist = Histogram::new(BUCKETS);
        context.register(
            "verify_duration",
            "Wall-clock duration of a full verify cycle",
            verify_hist.clone(),
        );

        let finalize_hist = Histogram::new(BUCKETS);
        context.register(
            "finalize_duration",
            "Wall-clock duration of a finalization",
            finalize_hist.clone(),
        );

        let rebuild_hist = Histogram::new(BUCKETS);
        context.register(
            "rebuild_pending_duration",
            "Wall-clock duration of lazy-recovery replays",
            rebuild_hist.clone(),
        );

        let rebuild_pending_depth = Gauge::default();
        context.register(
            "rebuild_pending_depth",
            "Blocks replayed during the most recent rebuild_pending",
            rebuild_pending_depth.clone(),
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
