//! Shared metrics for QMDB variants.

use commonware_runtime::{
    telemetry::metrics::{
        histogram::{duration_histogram, ScopedTimer, Timed},
        Counter, Gauge, GaugeExt as _, MetricsExt as _,
    },
    Clock, Metrics as RuntimeMetrics,
};
use std::sync::Arc;

/// State metrics common to operation-log databases.
pub(crate) struct StateMetrics {
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
}

impl StateMetrics {
    pub(crate) fn new<E: RuntimeMetrics>(context: &E) -> Self {
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
        }
    }

    /// Update state gauges.
    pub fn set(&self, size: u64, pruning_boundary: u64, inactivity_floor: u64, last_commit: u64) {
        let _ = self.size.try_set(size);
        let _ = self.pruning_boundary.try_set(pruning_boundary);
        let _ = self.retained.try_set(size.saturating_sub(pruning_boundary));
        let _ = self.inactivity_floor.try_set(inactivity_floor);
        let _ = self.last_commit.try_set(last_commit);
    }
}

/// Metrics for write and durability operations.
pub(crate) struct OperationMetrics<E: Clock> {
    /// Clock used for duration timers.
    clock: Arc<E>,
    /// Apply-batch calls.
    pub apply_batch_calls: Counter,
    /// Duration of apply-batch calls.
    apply_batch_duration: Timed,
    /// Operations written by completed batch applications.
    pub operations_applied: Counter,
    /// Durable commit calls.
    pub commit_calls: Counter,
    /// Duration of commit calls.
    commit_duration: Timed,
    /// Full sync calls.
    pub sync_calls: Counter,
    /// Duration of sync calls.
    sync_duration: Timed,
    /// Prune calls.
    pub prune_calls: Counter,
    /// Duration of prune calls.
    prune_duration: Timed,
}

impl<E: RuntimeMetrics + Clock> OperationMetrics<E> {
    pub(crate) fn new(context: Arc<E>) -> Self {
        let apply_batch_calls = context
            .as_ref()
            .counter("apply_batch_calls", "Number of apply-batch calls");
        let apply_batch_duration = duration_histogram(
            context.as_ref(),
            "apply_batch_duration",
            "Duration of apply-batch calls",
        );
        let operations_applied = context.as_ref().counter(
            "operations_applied",
            "Number of operations written by completed batch applications",
        );
        let commit_calls = context
            .as_ref()
            .counter("commit_calls", "Number of commit calls");
        let commit_duration = duration_histogram(
            context.as_ref(),
            "commit_duration",
            "Duration of commit calls",
        );
        let sync_calls = context
            .as_ref()
            .counter("sync_calls", "Number of sync calls");
        let sync_duration =
            duration_histogram(context.as_ref(), "sync_duration", "Duration of sync calls");
        let prune_calls = context
            .as_ref()
            .counter("prune_calls", "Number of prune calls");
        let prune_duration = duration_histogram(
            context.as_ref(),
            "prune_duration",
            "Duration of prune calls",
        );
        Self {
            clock: context,
            apply_batch_calls,
            apply_batch_duration: Timed::new(apply_batch_duration),
            operations_applied,
            commit_calls,
            commit_duration: Timed::new(commit_duration),
            sync_calls,
            sync_duration: Timed::new(sync_duration),
            prune_calls,
            prune_duration: Timed::new(prune_duration),
        }
    }
}

impl<E: Clock> OperationMetrics<E> {
    pub(crate) fn apply_batch_timer(&self) -> ScopedTimer<E> {
        self.apply_batch_duration.scoped(&self.clock)
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
}

/// Metrics for key-based reads.
pub(crate) struct KeyReadMetrics<E: Clock> {
    /// Clock used for duration timers.
    clock: Arc<E>,
    /// Single-key get calls.
    pub get_calls: Counter,
    /// Duration of single-key get calls.
    get_duration: Timed,
    /// Non-empty get-many calls.
    pub get_many_calls: Counter,
    /// Duration of non-empty get-many calls.
    get_many_duration: Timed,
    /// Keys requested by read paths, whether or not they are found.
    pub keys_requested: Counter,
}

impl<E: RuntimeMetrics + Clock> KeyReadMetrics<E> {
    pub(crate) fn new(context: Arc<E>) -> Self {
        let get_calls = context.as_ref().counter("get_calls", "Number of get calls");
        let get_duration =
            duration_histogram(context.as_ref(), "get_duration", "Duration of get calls");
        let get_many_calls = context
            .as_ref()
            .counter("get_many_calls", "Number of non-empty get-many calls");
        let get_many_duration = duration_histogram(
            context.as_ref(),
            "get_many_duration",
            "Duration of non-empty get-many calls",
        );
        let keys_requested = context.as_ref().counter(
            "keys_requested",
            "Number of keys requested by get/get-many calls, including misses",
        );
        Self {
            clock: context,
            get_calls,
            get_duration: Timed::new(get_duration),
            get_many_calls,
            get_many_duration: Timed::new(get_many_duration),
            keys_requested,
        }
    }
}

impl<E: Clock> KeyReadMetrics<E> {
    pub(crate) fn get_timer(&self) -> ScopedTimer<E> {
        self.get_duration.scoped(&self.clock)
    }

    pub(crate) fn get_many_timer(&self) -> ScopedTimer<E> {
        self.get_many_duration.scoped(&self.clock)
    }
}

/// Metrics for location-based reads.
pub(crate) struct LocationReadMetrics<E: Clock> {
    /// Clock used for duration timers.
    clock: Arc<E>,
    /// Single-location get calls.
    pub get_calls: Counter,
    /// Duration of single-location get calls.
    get_duration: Timed,
    /// Non-empty get-many calls.
    pub get_many_calls: Counter,
    /// Duration of non-empty get-many calls.
    get_many_duration: Timed,
    /// Locations requested by read paths, whether or not they are found.
    pub locations_requested: Counter,
}

impl<E: RuntimeMetrics + Clock> LocationReadMetrics<E> {
    pub(crate) fn new(context: Arc<E>) -> Self {
        let get_calls = context.as_ref().counter("get_calls", "Number of get calls");
        let get_duration =
            duration_histogram(context.as_ref(), "get_duration", "Duration of get calls");
        let get_many_calls = context
            .as_ref()
            .counter("get_many_calls", "Number of non-empty get-many calls");
        let get_many_duration = duration_histogram(
            context.as_ref(),
            "get_many_duration",
            "Duration of non-empty get-many calls",
        );
        let locations_requested = context.as_ref().counter(
            "locations_requested",
            "Number of locations requested by get/get-many calls, including misses",
        );
        Self {
            clock: context,
            get_calls,
            get_duration: Timed::new(get_duration),
            get_many_calls,
            get_many_duration: Timed::new(get_many_duration),
            locations_requested,
        }
    }
}

impl<E: Clock> LocationReadMetrics<E> {
    pub(crate) fn get_timer(&self) -> ScopedTimer<E> {
        self.get_duration.scoped(&self.clock)
    }

    pub(crate) fn get_many_timer(&self) -> ScopedTimer<E> {
        self.get_many_duration.scoped(&self.clock)
    }
}
