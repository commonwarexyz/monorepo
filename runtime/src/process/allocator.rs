//! Allocator metrics collected from mimalloc.
//!
//! The statistics are process-wide (mimalloc keeps one accounting across
//! every heap and thread), so a process with several runtimes reports the
//! same values through each of them, like [`super::metered::Metrics::rss`].
//! Cumulative quantities are exported as counters fed by deltas between
//! reads, which keeps several collectors in one process correct.
//!
//! Nothing here installs an allocator: the family is registered only when a
//! probe allocation shows that the process's global allocator is the mimalloc
//! linked through `commonware-allocator`, installed through its `MiMalloc`
//! directly or wrapped by another allocator. A different mimalloc build
//! cannot be linked alongside it.
//!
//! Freshness: memory accounting against the operating system (reserved,
//! committed, purged, mappings) is updated immediately, while per-thread
//! counters (pages, huge allocations) are merged into the process totals
//! when each thread collects, which mimalloc does periodically on its own
//! allocation path or when the thread exits. Those values can therefore lag
//! behind a thread that allocates rarely.

use crate::telemetry::metrics::{Counter, Gauge, GaugeExt, Register, raw};
use commonware_allocator::mimalloc::{self, Stats};
use tracing::warn;

/// Gauges and counters derived from [`Stats`].
pub struct Metrics {
    reserved_bytes: Gauge,
    pinned_bytes: Gauge,
    committed_bytes: Gauge,
    committed_peak_bytes: Gauge,
    resident_bytes: Gauge,
    pages: Gauge,
    threads: Gauge,
    arenas: Gauge,
    purged_bytes: Counter,
    purge_calls: Counter,
    mmap_calls: Counter,
    huge_allocations: Counter,
    huge_bytes: Counter,
    page_faults: Counter,
    /// Last statistics applied, so cumulative values can be fed as deltas.
    last: Stats,
}

impl Metrics {
    /// Registers the allocator family if mimalloc is the global allocator.
    ///
    /// Returns `None`, after logging a warning, when it is not: the feature
    /// was enabled but the binary installed a different allocator, so the
    /// statistics would describe memory nobody uses.
    pub fn init(registry: &mut impl Register) -> Option<Self> {
        if !mimalloc::is_global_allocator() {
            warn!("mimalloc metrics enabled but mimalloc is not the global allocator");
            return None;
        }
        let mut register_gauge = |name: &str, help: &str| -> Gauge {
            registry.register(name, help, raw::Gauge::default())
        };
        let reserved_bytes = register_gauge(
            "allocator_reserved_bytes",
            "Bytes the allocator reserved from the operating system",
        );
        let pinned_bytes = register_gauge(
            "allocator_pinned_bytes",
            "Bytes of pinned reservations the allocator never purges",
        );
        let committed_bytes = register_gauge(
            "allocator_committed_bytes",
            "Bytes the allocator currently has committed",
        );
        let committed_peak_bytes = register_gauge(
            "allocator_committed_peak_bytes",
            "Peak bytes the allocator has had committed",
        );
        let resident_bytes = register_gauge(
            "allocator_resident_bytes",
            "Resident set size as seen by the allocator",
        );
        let pages = register_gauge("allocator_pages", "Allocator pages currently in use");
        let threads = register_gauge(
            "allocator_threads",
            "Threads currently known to the allocator",
        );
        let arenas = register_gauge(
            "allocator_arenas",
            "Arenas currently managed by the allocator",
        );
        // Counters are registered without the `_total` suffix because the
        // prometheus encoder appends it to counter names.
        let mut register_counter = |name: &str, help: &str| -> Counter {
            registry.register(name, help, raw::Counter::default())
        };
        let purged_bytes = register_counter(
            "allocator_purged_bytes",
            "Total bytes the allocator purged back to the operating system",
        );
        let purge_calls = register_counter(
            "allocator_purge_calls",
            "Total purge operations performed by the allocator",
        );
        let mmap_calls = register_counter(
            "allocator_mmap_calls",
            "Total memory mappings the allocator requested from the operating system",
        );
        let huge_allocations = register_counter(
            "allocator_huge_allocations",
            "Total allocations larger than the allocator's largest size class",
        );
        let huge_bytes = register_counter(
            "allocator_huge_bytes",
            "Total bytes of allocations larger than the allocator's largest size class",
        );
        let page_faults = register_counter(
            "allocator_page_faults",
            "Total page faults reported to the allocator",
        );
        let mut metrics = Self {
            reserved_bytes,
            pinned_bytes,
            committed_bytes,
            committed_peak_bytes,
            resident_bytes,
            pages,
            threads,
            arenas,
            purged_bytes,
            purge_calls,
            mmap_calls,
            huge_allocations,
            huge_bytes,
            page_faults,
            last: Stats::default(),
        };
        metrics.update();
        Some(metrics)
    }

    /// Reads the current statistics into the metrics.
    pub fn update(&mut self) {
        let Some(stats) = Stats::read() else {
            return;
        };
        let _ = self.reserved_bytes.try_set(stats.reserved_bytes);
        let _ = self.pinned_bytes.try_set(stats.pinned_bytes);
        let _ = self.committed_bytes.try_set(stats.committed_bytes);
        let _ = self
            .committed_peak_bytes
            .try_set(stats.committed_peak_bytes);
        let _ = self.resident_bytes.try_set(stats.resident_bytes);
        let _ = self.pages.try_set(stats.pages);
        let _ = self.threads.try_set(stats.threads);
        let _ = self.arenas.try_set(stats.arenas);
        let last = self.last;
        self.purged_bytes
            .inc_by(stats.purged_bytes.saturating_sub(last.purged_bytes));
        self.purge_calls
            .inc_by(stats.purge_calls.saturating_sub(last.purge_calls));
        self.mmap_calls
            .inc_by(stats.mmap_calls.saturating_sub(last.mmap_calls));
        self.huge_allocations
            .inc_by(stats.huge_allocations.saturating_sub(last.huge_allocations));
        self.huge_bytes
            .inc_by(stats.huge_bytes.saturating_sub(last.huge_bytes));
        self.page_faults
            .inc_by(stats.page_faults.saturating_sub(last.page_faults));
        self.last = stats;
    }
}
