//! Metrics for QMDB variants.

use commonware_runtime::{
    Clock, Metrics as RuntimeMetrics,
    telemetry::metrics::{
        Counter, Gauge, GaugeExt as _, MetricsExt as _,
        histogram::{ScopedTimer, Timed},
    },
};
use std::sync::Arc;

/// Metrics for an operation-log database.
///
/// All QMDB variants register the same set. Sub-components (the operation log, index, and
/// grafted layers) register their own metrics under their own contexts.
pub(crate) struct Metrics<E: Clock> {
    /// Logical operation end.
    size: Gauge,
    /// Oldest retained operation location.
    pruning_boundary: Gauge,
    /// Retained operation count.
    retained: Gauge,
    /// Application-declared pruning floor location.
    inactivity_floor: Gauge,
    /// Most recent commit operation location.
    last_commit: Gauge,
    /// Apply-batch calls.
    pub apply_batch_calls: Counter,
    /// Duration of apply-batch calls.
    apply_batch_duration: Timed,
    /// Operations written by completed batch applications.
    pub operations_applied: Counter,
    /// Point get calls.
    pub get_calls: Counter,
    /// Duration of point get calls.
    get_duration: Timed,
    /// Non-empty get-many calls.
    pub get_many_calls: Counter,
    /// Duration of non-empty get-many calls.
    get_many_duration: Timed,
    /// Lookups requested by read paths, whether or not they are found.
    pub lookups_requested: Counter,
    /// Durable commit calls.
    pub commit_calls: Counter,
    /// Duration of commit calls.
    commit_duration: Timed,
    /// Pipelined syncs begun via `start_sync`.
    pub start_sync_calls: Counter,
    /// Full sync calls.
    pub sync_calls: Counter,
    /// Duration of sync calls.
    sync_duration: Timed,
    /// Prune calls.
    pub prune_calls: Counter,
    /// Duration of prune calls.
    prune_duration: Timed,
    /// Clock used by the duration timers.
    clock: Arc<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Register the full metric set under `context`, retaining it as the timers' clock.
    pub(crate) fn new(context: E) -> Self {
        Self {
            size: context.gauge("size", "Logical operation end"),
            pruning_boundary: context
                .gauge("pruning_boundary", "Oldest retained operation location"),
            retained: context.gauge("retained", "Number of retained operations"),
            inactivity_floor: context.gauge(
                "inactivity_floor",
                "Application-declared pruning floor location",
            ),
            last_commit: context.gauge("last_commit", "Most recent commit operation location"),
            apply_batch_calls: context.counter("apply_batch_calls", "Number of apply-batch calls"),
            apply_batch_duration: Timed::register(
                &context,
                "apply_batch_duration",
                "Duration of apply-batch calls",
            ),
            operations_applied: context.counter(
                "operations_applied",
                "Number of operations written by completed batch applications",
            ),
            get_calls: context.counter("get_calls", "Number of get calls"),
            get_duration: Timed::register(&context, "get_duration", "Duration of get calls"),
            get_many_calls: context.counter("get_many_calls", "Number of non-empty get-many calls"),
            get_many_duration: Timed::register(
                &context,
                "get_many_duration",
                "Duration of non-empty get-many calls",
            ),
            lookups_requested: context.counter(
                "lookups_requested",
                "Number of lookups requested by get/get-many calls, including misses",
            ),
            commit_calls: context.counter("commit_calls", "Number of commit calls"),
            commit_duration: Timed::register(
                &context,
                "commit_duration",
                "Duration of commit calls",
            ),
            start_sync_calls: context.counter("start_sync_calls", "Number of start_sync calls"),
            sync_calls: context.counter("sync_calls", "Number of sync calls"),
            sync_duration: Timed::register(&context, "sync_duration", "Duration of sync calls"),
            prune_calls: context.counter("prune_calls", "Number of prune calls"),
            prune_duration: Timed::register(&context, "prune_duration", "Duration of prune calls"),
            clock: Arc::new(context),
        }
    }
}

impl<E: Clock> Metrics<E> {
    pub(crate) fn apply_batch_timer(&self) -> ScopedTimer<E> {
        self.apply_batch_duration.scoped(&self.clock)
    }

    pub(crate) fn get_timer(&self) -> ScopedTimer<E> {
        self.get_duration.scoped(&self.clock)
    }

    pub(crate) fn get_many_timer(&self) -> ScopedTimer<E> {
        self.get_many_duration.scoped(&self.clock)
    }

    pub(crate) fn commit_timer(&self) -> ScopedTimer<E> {
        self.commit_duration.scoped(&self.clock)
    }

    pub(crate) fn sync_timer(&self) -> ScopedTimer<E> {
        self.sync_duration.scoped(&self.clock)
    }

    pub(crate) fn prune_timer(&self) -> ScopedTimer<E> {
        self.prune_duration.scoped(&self.clock)
    }

    /// Update state gauges.
    pub(crate) fn update(
        &self,
        size: u64,
        pruning_boundary: u64,
        inactivity_floor: u64,
        last_commit: u64,
    ) {
        let _ = self.size.try_set(size);
        let _ = self.pruning_boundary.try_set(pruning_boundary);
        let _ = self.retained.try_set(size.saturating_sub(pruning_boundary));
        let _ = self.inactivity_floor.try_set(inactivity_floor);
        let _ = self.last_commit.try_set(last_commit);
    }
}
