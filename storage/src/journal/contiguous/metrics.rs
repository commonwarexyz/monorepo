//! Metrics for contiguous journals.

use crate::metrics::{duration_histogram, timer, Timed, Timer};
use commonware_runtime::{
    telemetry::metrics::{Counter, Gauge, GaugeExt as _, MetricsExt as _},
    Clock, Metrics as RuntimeMetrics,
};
use std::{ops::Deref, sync::Arc};

/// Metrics registered only for fixed-size journals.
pub(super) struct CacheMetrics {
    /// Fixed items read without async storage fallback.
    hits: Counter,
    /// Fixed items not satisfied synchronously: misses inside `read_many` plus
    /// all `try_read_sync` calls that returned `None`, including invalid or pruned probes.
    misses: Counter,
}

/// Metrics registered only for variable-size journals.
pub(super) struct CommitMetrics {
    /// Durable commit calls that do not fully sync all indexes.
    calls: Counter,
    /// Duration of commit calls that do not fully sync all indexes.
    duration: Timed,
}

/// Metrics common to contiguous journal implementations.
pub(super) struct CommonMetrics<E: Clock> {
    /// Clock used for duration timers.
    clock: Arc<E>,
    /// Logical end position.
    pub size: Gauge,
    /// Oldest readable item position.
    pub pruning_boundary: Gauge,
    /// Readable items retained.
    pub retained: Gauge,
    /// Items in the section containing the newest retained item.
    pub tail_items: Gauge,
    /// Single-item append calls.
    pub append_calls: Counter,
    /// Duration of single-item append calls.
    append_duration: Timed,
    /// Append-many calls.
    pub append_many_calls: Counter,
    /// Duration of append-many calls.
    append_many_duration: Timed,
    /// Single-item async read calls.
    pub read_calls: Counter,
    /// Duration of single-item read calls.
    read_duration: Timed,
    /// Non-empty batch async read calls.
    pub read_many_calls: Counter,
    /// Duration of non-empty batch read calls.
    read_many_duration: Timed,
    /// Successful `try_read_sync` calls.
    pub try_read_sync_hits: Counter,
    /// Items returned by read, read_many, and try_read_sync.
    pub items_read: Counter,
    /// Full sync calls.
    pub sync_calls: Counter,
    /// Duration of full sync calls.
    sync_duration: Timed,
}

impl<E: RuntimeMetrics + Clock> CommonMetrics<E> {
    fn new(context: Arc<E>) -> Self {
        let size = context
            .as_ref()
            .gauge("size", "Logical end position of the journal");
        let pruning_boundary = context
            .as_ref()
            .gauge("pruning_boundary", "Oldest readable item position");
        let retained = context
            .as_ref()
            .gauge("retained", "Number of readable items retained");
        let tail_items = context.as_ref().gauge(
            "tail_items",
            "Items in the section containing the newest retained item",
        );
        let append_calls = context
            .as_ref()
            .counter("append_calls", "Number of single-item append calls");
        let append_duration = duration_histogram(
            context.as_ref(),
            "append_duration",
            "Duration of single-item append calls",
        );
        let append_many_calls = context
            .as_ref()
            .counter("append_many_calls", "Number of append-many calls");
        let append_many_duration = duration_histogram(
            context.as_ref(),
            "append_many_duration",
            "Duration of append-many calls",
        );
        let read_calls = context
            .as_ref()
            .counter("read_calls", "Number of single-item read calls");
        let read_duration = duration_histogram(
            context.as_ref(),
            "read_duration",
            "Duration of single-item read calls",
        );
        let read_many_calls = context
            .as_ref()
            .counter("read_many_calls", "Number of non-empty batch read calls");
        let read_many_duration = duration_histogram(
            context.as_ref(),
            "read_many_duration",
            "Duration of non-empty batch read calls",
        );
        let try_read_sync_hits = context.as_ref().counter(
            "try_read_sync_hits",
            "Number of try_read_sync calls that returned Some",
        );
        let items_read = context.as_ref().counter(
            "items_read",
            "Number of items returned by read, read_many, and try_read_sync",
        );
        let sync_calls = context
            .as_ref()
            .counter("sync_calls", "Number of sync calls");
        let sync_duration = duration_histogram(
            context.as_ref(),
            "sync_duration",
            "Duration of full sync calls",
        );
        Self {
            clock: context,
            size,
            pruning_boundary,
            retained,
            tail_items,
            append_calls,
            append_duration: Timed::new(append_duration),
            append_many_calls,
            append_many_duration: Timed::new(append_many_duration),
            read_calls,
            read_duration: Timed::new(read_duration),
            read_many_calls,
            read_many_duration: Timed::new(read_many_duration),
            try_read_sync_hits,
            items_read,
            sync_calls,
            sync_duration: Timed::new(sync_duration),
        }
    }
}

impl<E: Clock> CommonMetrics<E> {
    pub(super) fn append_timer(&self) -> Timer<E> {
        timer(&self.append_duration, &self.clock)
    }

    pub(super) fn append_many_timer(&self) -> Timer<E> {
        timer(&self.append_many_duration, &self.clock)
    }

    pub(super) fn read_timer(&self) -> Timer<E> {
        timer(&self.read_duration, &self.clock)
    }

    pub(super) fn read_many_timer(&self) -> Timer<E> {
        timer(&self.read_many_duration, &self.clock)
    }

    pub(super) fn sync_timer(&self) -> Timer<E> {
        timer(&self.sync_duration, &self.clock)
    }

    /// Update state gauges from current bounds.
    pub(super) fn update(&self, size: u64, pruning_boundary: u64, items_per_section: u64) {
        let _ = self.size.try_set(size);
        let _ = self.pruning_boundary.try_set(pruning_boundary);
        let _ = self.retained.try_set(size.saturating_sub(pruning_boundary));
        let tail_items = if size == pruning_boundary {
            0
        } else {
            let tail_section_start = ((size - 1) / items_per_section) * items_per_section;
            size - pruning_boundary.max(tail_section_start)
        };
        let _ = self.tail_items.try_set(tail_items);
    }
}

/// Metrics for fixed-size contiguous journals.
pub(super) struct FixedMetrics<E: Clock> {
    common: CommonMetrics<E>,
    cache: CacheMetrics,
}

impl<E: RuntimeMetrics + Clock> FixedMetrics<E> {
    /// Create and register metrics for a fixed-size journal.
    pub(super) fn new(context: E) -> Self {
        let context = Arc::new(context);
        let hits = context
            .as_ref()
            .counter("cache_hits", "Number of fixed items read synchronously");
        let misses = context.as_ref().counter(
            "cache_misses",
            "Number of fixed items not satisfied synchronously, including pruned or out-of-range \
             try_read_sync probes that returned None",
        );
        let common = CommonMetrics::new(context);
        Self {
            common,
            cache: CacheMetrics { hits, misses },
        }
    }
}

impl<E: Clock> FixedMetrics<E> {
    pub(super) fn record_cache_hits(&self, hits: u64) {
        self.cache.hits.inc_by(hits);
    }

    pub(super) fn record_cache_misses(&self, misses: u64) {
        self.cache.misses.inc_by(misses);
    }
}

impl<E: Clock> Deref for FixedMetrics<E> {
    type Target = CommonMetrics<E>;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}

/// Metrics for variable-size contiguous journals.
pub(super) struct VariableMetrics<E: Clock> {
    common: CommonMetrics<E>,
    commit: CommitMetrics,
}

impl<E: RuntimeMetrics + Clock> VariableMetrics<E> {
    /// Create and register metrics for a variable-size journal.
    pub(super) fn new(context: E) -> Self {
        let context = Arc::new(context);
        let calls = context
            .as_ref()
            .counter("commit_calls", "Number of commit calls");
        let duration = duration_histogram(
            context.as_ref(),
            "commit_duration",
            "Duration of commit calls",
        );
        Self {
            common: CommonMetrics::new(context),
            commit: CommitMetrics {
                calls,
                duration: Timed::new(duration),
            },
        }
    }
}

impl<E: Clock> VariableMetrics<E> {
    pub(super) fn commit_timer(&self) -> Timer<E> {
        timer(&self.commit.duration, &self.common.clock)
    }

    pub(super) fn record_commit(&self) {
        self.commit.calls.inc();
    }
}

impl<E: Clock> Deref for VariableMetrics<E> {
    type Target = CommonMetrics<E>;

    fn deref(&self) -> &Self::Target {
        &self.common
    }
}
