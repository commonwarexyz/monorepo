//! Metrics for contiguous journals.

use commonware_runtime::{
    telemetry::metrics::{
        histogram::{ScopedTimer, Timed},
        Counter, Gauge, GaugeExt as _, MetricsExt as _,
    },
    Clock, Metrics as RuntimeMetrics,
};
use std::sync::Arc;

/// Metrics for a contiguous journal.
///
/// Fixed and variable journals register the same set. The variable journal's offsets journal
/// registers its own set under a child context.
pub(super) struct Metrics<E: Clock> {
    /// Logical end position.
    size: Gauge,
    /// Oldest readable item position.
    pruning_boundary: Gauge,
    /// Readable items retained.
    retained: Gauge,
    /// Items in the blob containing the newest retained item.
    tail_items: Gauge,
    /// Single-item append calls.
    pub append_calls: Counter,
    /// Duration of single-item append calls.
    append_duration: Timed,
    /// Append-many calls.
    pub append_many_calls: Counter,
    /// Duration of append-many calls.
    append_many_duration: Timed,
    /// Pre-encoded batch append calls.
    pub append_prepared_calls: Counter,
    /// Duration of pre-encoded batch append calls.
    append_prepared_duration: Timed,
    /// Single-item read calls.
    pub read_calls: Counter,
    /// Duration of single-item read calls that miss the page cache.
    read_duration: Timed,
    /// Non-empty batch async read calls.
    pub read_many_calls: Counter,
    /// Duration of non-empty batch read calls.
    read_many_duration: Timed,
    /// Items read without async storage fallback.
    pub cache_hits: Counter,
    /// Items that fell back to a blob read in `read` and `read_many`. Declined probes
    /// (`try_read_sync` and `try_read_many_sync`) count hits only, never misses.
    pub cache_misses: Counter,
    /// Items returned by read, read_many, try_read_sync, and try_read_many_sync.
    pub items_read: Counter,
    /// Full sync calls.
    pub sync_calls: Counter,
    /// Duration of full sync calls.
    sync_duration: Timed,
    /// Clock used by the duration timers.
    clock: Arc<E>,
}

impl<E: RuntimeMetrics + Clock> Metrics<E> {
    /// Register the full metric set under `context`, retaining it as the timers' clock.
    pub(super) fn new(context: E) -> Self {
        Self {
            size: context.gauge("size", "Logical end position of the journal"),
            pruning_boundary: context.gauge("pruning_boundary", "Oldest readable item position"),
            retained: context.gauge("retained", "Number of readable items retained"),
            tail_items: context.gauge(
                "tail_items",
                "Items in the blob containing the newest retained item",
            ),
            append_calls: context.counter("append_calls", "Number of single-item append calls"),
            append_duration: Timed::register(
                &context,
                "append_duration",
                "Duration of single-item append calls",
            ),
            append_many_calls: context.counter("append_many_calls", "Number of append-many calls"),
            append_many_duration: Timed::register(
                &context,
                "append_many_duration",
                "Duration of append-many calls",
            ),
            append_prepared_calls: context.counter(
                "append_prepared_calls",
                "Number of pre-encoded batch append calls",
            ),
            append_prepared_duration: Timed::register(
                &context,
                "append_prepared_duration",
                "Duration of pre-encoded batch append calls",
            ),
            read_calls: context.counter("read_calls", "Number of single-item read calls"),
            read_duration: Timed::register(
                &context,
                "read_duration",
                "Duration of single-item read calls that miss the page cache",
            ),
            read_many_calls: context
                .counter("read_many_calls", "Number of non-empty batch read calls"),
            read_many_duration: Timed::register(
                &context,
                "read_many_duration",
                "Duration of non-empty batch read calls",
            ),
            cache_hits: context.counter("cache_hits", "Number of items served without a blob read"),
            cache_misses: context.counter("cache_misses", "Number of items requiring a blob read"),
            items_read: context.counter(
                "items_read",
                "Number of items returned by point reads, batch reads, and sync probes",
            ),
            sync_calls: context.counter("sync_calls", "Number of sync calls"),
            sync_duration: Timed::register(
                &context,
                "sync_duration",
                "Duration of full sync calls",
            ),
            clock: Arc::new(context),
        }
    }
}

impl<E: Clock> Metrics<E> {
    pub(super) fn append_timer(&self) -> ScopedTimer<E> {
        self.append_duration.scoped(&self.clock)
    }

    pub(super) fn append_many_timer(&self) -> ScopedTimer<E> {
        self.append_many_duration.scoped(&self.clock)
    }

    pub(super) fn append_prepared_timer(&self) -> ScopedTimer<E> {
        self.append_prepared_duration.scoped(&self.clock)
    }

    pub(super) fn read_timer(&self) -> ScopedTimer<E> {
        self.read_duration.scoped(&self.clock)
    }

    pub(super) fn read_many_timer(&self) -> ScopedTimer<E> {
        self.read_many_duration.scoped(&self.clock)
    }

    pub(super) fn sync_timer(&self) -> ScopedTimer<E> {
        self.sync_duration.scoped(&self.clock)
    }

    /// Update state gauges from current bounds: every item lives in ONE blob, so the tail
    /// gauge equals the retained count.
    pub(super) fn update(&self, size: u64, pruning_boundary: u64) {
        let _ = self.size.try_set(size);
        let _ = self.pruning_boundary.try_set(pruning_boundary);
        let retained = size.saturating_sub(pruning_boundary);
        let _ = self.retained.try_set(retained);
        let _ = self.tail_items.try_set(retained);
    }
}
