//! Metrics for the [`Processor`](super::Processor).

use commonware_runtime::{
    telemetry::metrics::{
        raw, CounterFamily, EncodeLabelSet, EncodeLabelValue, GaugeExt, HistogramExt,
        MetricsExt, Registered,
        histogram::Timed,
    },
    Clock, Metrics as MetricsTrait,
};
use prometheus_client::metrics::{counter::Counter, gauge::Gauge, histogram::Histogram};
use std::time::SystemTime;

/// Buckets for histograms.
///
/// These buckets are much less coarse than [`Buckets::LOCAL`].
///
/// [`Buckets::LOCAL`]: commonware_runtime::telemetry::metrics::histogram::Buckets::LOCAL
const BUCKETS: [f64; 10] = [0.001, 0.01, 0.025, 0.05, 0.075, 0.1, 0.25, 0.5, 0.75, 1.0];

type MaintenanceDuration =
    Registered<raw::Family<MaintenanceLabel, raw::Histogram, fn() -> raw::Histogram>>;

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(in crate::stateful::actor) enum MaintenanceKind {
    Preflush,
    Prune,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelValue)]
pub(in crate::stateful::actor) enum MaintenanceOutcome {
    Complete,
    Failed,
    NotStarted,
    PreflushStarted,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct MaintenanceLabel {
    action: MaintenanceKind,
}

#[derive(Clone, Copy, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
struct MaintenanceCompletionLabel {
    action: MaintenanceKind,
    outcome: MaintenanceOutcome,
}

fn maintenance_duration_histogram() -> raw::Histogram {
    raw::Histogram::new(BUCKETS)
}

/// Metrics for the stateful processor.
///
/// All duration histograms use [`Timed`] wrappers for automatic recording via
/// [`Timer`](commonware_runtime::telemetry::metrics::histogram::Timer).
#[derive(Clone)]
pub(crate) struct Metrics {
    /// Current number of entries in the in-memory pending map.
    pub pending_blocks: Registered<Gauge>,

    /// Total pending entries pruned after finalizations.
    pub pruned_forks: Registered<Counter>,

    /// Wall-clock duration of a full propose cycle.
    pub propose_duration: Timed,

    /// Wall-clock duration of a full verify cycle.
    pub verify_duration: Timed,

    /// Wall-clock duration of a finalization.
    pub finalize_duration: Timed,

    /// Wall-clock duration of lazy-recovery replays via `rebuild_pending`.
    pub rebuild_pending_duration: Timed,

    /// Number of blocks replayed during the most recent `rebuild_pending` call.
    pub rebuild_pending_depth: Registered<Gauge>,

    /// Current number of maintenance actions queued behind the running task.
    pub maintenance_pending: Registered<Gauge>,

    /// Whether a maintenance task is currently running.
    pub maintenance_running: Registered<Gauge>,

    /// Deferred maintenance actions returned by finalization.
    maintenance_scheduled: CounterFamily<MaintenanceLabel>,

    /// Deferred maintenance actions started by the actor.
    maintenance_started: CounterFamily<MaintenanceLabel>,

    /// Deferred maintenance task completions by outcome.
    maintenance_completed: CounterFamily<MaintenanceCompletionLabel>,

    /// Wall-clock duration of deferred maintenance tasks.
    maintenance_duration: MaintenanceDuration,
}

impl Metrics {
    /// Create and register all processor metrics.
    ///
    /// The provided `context` is cloned internally to avoid further nesting the
    /// label hierarchy.
    pub fn new<E: MetricsTrait>(context: E) -> Self {
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

        let maintenance_pending = context.register(
            "maintenance_pending",
            "Current deferred maintenance actions queued behind the running task",
            Gauge::default(),
        );

        let maintenance_running = context.register(
            "maintenance_running",
            "Whether a deferred maintenance task is currently running",
            Gauge::default(),
        );

        let maintenance_scheduled = context.family(
            "maintenance_scheduled",
            "Deferred maintenance actions returned by finalization",
        );

        let maintenance_started = context.family(
            "maintenance_started",
            "Deferred maintenance actions started by the actor",
        );

        let maintenance_completed = context.family(
            "maintenance_completed",
            "Deferred maintenance task completions by outcome",
        );

        let maintenance_duration = context.register(
            "maintenance_duration",
            "Wall-clock duration of deferred maintenance tasks",
            raw::Family::<MaintenanceLabel, raw::Histogram, fn() -> raw::Histogram>::new_with_constructor(
                maintenance_duration_histogram,
            ),
        );

        Self {
            pending_blocks,
            pruned_forks,
            propose_duration: Timed::new(propose_hist),
            verify_duration: Timed::new(verify_hist),
            finalize_duration: Timed::new(finalize_hist),
            rebuild_pending_duration: Timed::new(rebuild_hist),
            rebuild_pending_depth,
            maintenance_pending,
            maintenance_running,
            maintenance_scheduled,
            maintenance_started,
            maintenance_completed,
            maintenance_duration,
        }
    }

    pub(in crate::stateful::actor) fn set_maintenance_pending(&self, pending: usize) {
        let _ = self.maintenance_pending.try_set(pending);
    }

    pub(in crate::stateful::actor) fn set_maintenance_running(&self, running: bool) {
        let _ = self
            .maintenance_running
            .try_set(if running { 1 } else { 0 });
    }

    pub(in crate::stateful::actor) fn maintenance_scheduled(&self, action: MaintenanceKind) {
        self.maintenance_scheduled
            .get_or_create(&MaintenanceLabel { action })
            .inc();
    }

    pub(in crate::stateful::actor) fn maintenance_started(&self, action: MaintenanceKind) {
        self.maintenance_started
            .get_or_create(&MaintenanceLabel { action })
            .inc();
    }

    pub(in crate::stateful::actor) fn maintenance_completed(
        &self,
        action: MaintenanceKind,
        outcome: MaintenanceOutcome,
    ) {
        self.maintenance_completed
            .get_or_create(&MaintenanceCompletionLabel { action, outcome })
            .inc();
    }

    pub(in crate::stateful::actor) fn observe_maintenance_duration<C: Clock>(
        &self,
        action: MaintenanceKind,
        start: SystemTime,
        clock: &C,
    ) {
        self.maintenance_duration
            .get_or_create(&MaintenanceLabel { action })
            .observe_between(start, clock.current());
    }
}

#[cfg(test)]
mod tests {
    use super::{MaintenanceKind, MaintenanceOutcome, Metrics};
    use commonware_runtime::{Clock as _, Metrics as _, Runner as _, Supervisor as _, deterministic};
    use std::time::Duration;

    #[test]
    fn maintenance_metrics_are_recorded() {
        deterministic::Runner::default().start(|context| async move {
            let metrics = Metrics::new(context.child("processor"));
            metrics.set_maintenance_pending(2);
            metrics.set_maintenance_running(true);
            metrics.maintenance_scheduled(MaintenanceKind::Preflush);
            metrics.maintenance_started(MaintenanceKind::Preflush);
            let start = context.current();
            context.sleep(Duration::from_millis(1)).await;
            metrics.observe_maintenance_duration(MaintenanceKind::Preflush, start, &context);
            metrics.maintenance_completed(
                MaintenanceKind::Preflush,
                MaintenanceOutcome::PreflushStarted,
            );

            let output = context.encode();
            assert!(
                output.contains("processor_maintenance_pending 2"),
                "{output}"
            );
            assert!(
                output.contains("processor_maintenance_running 1"),
                "{output}"
            );
            assert!(
                output.contains("processor_maintenance_scheduled_total{action=\"Preflush\"} 1"),
                "{output}"
            );
            assert!(
                output.contains("processor_maintenance_started_total{action=\"Preflush\"} 1"),
                "{output}"
            );
            assert!(
                output.contains(
                    "processor_maintenance_completed_total{action=\"Preflush\",outcome=\"PreflushStarted\"} 1"
                ),
                "{output}"
            );
            assert!(
                output.contains("processor_maintenance_duration_count{action=\"Preflush\"} 1"),
                "{output}"
            );
        });
    }
}
