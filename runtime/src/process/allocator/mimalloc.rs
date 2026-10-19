//! Metrics collected from mimalloc.
//!
//! The allocator crate names the exported statistics in
//! [`commonware_allocator::mimalloc::metrics::METRICS`]. This module registers
//! them under the `allocator` family and refreshes them from one [`Stats`]
//! snapshot each collection. The statistics are process-wide (mimalloc keeps
//! one accounting across every heap and thread), so a process with several
//! runtimes reports the same values through each of them, like
//! [`super::super::metered::Metrics::rss`]. Counters are raised to the cumulative
//! value read.
//!
//! Nothing here installs an allocator: the family is registered only when a
//! probe allocation shows that the process's global allocator is the
//! [`commonware_allocator::mimalloc::MiMalloc`], installed directly or
//! wrapped by another allocator. Cargo admits one crate with
//! `links = "mimalloc"` per build, so no other mimalloc can be linked
//! alongside it.
//!
//! Freshness: memory accounting against the operating system (reserved,
//! committed, purged, mappings) is updated immediately, while per-thread
//! counters (pages, huge allocations) are merged into the process totals
//! when each thread collects, which mimalloc does periodically on its own
//! allocation path or when the thread exits. Those values can therefore lag
//! behind a thread that allocates rarely.

use crate::telemetry::metrics::{Counter, Gauge, GaugeExt, Register, raw};
use commonware_allocator::mimalloc::{
    self, Stats,
    metrics::{Kind, METRICS},
};
use std::sync::atomic::Ordering;
use tracing::warn;

/// Reads one statistic from a snapshot.
type Read = fn(&Stats) -> u64;

/// The registered series, each with the statistic that feeds it.
pub struct Metrics {
    gauges: Vec<(Gauge, Read)>,
    counters: Vec<(Counter, Read)>,
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
        let mut registry = registry.sub_registry("allocator");
        let mut gauges = Vec::new();
        let mut counters = Vec::new();
        for metric in &METRICS {
            match metric.kind {
                Kind::Gauge => {
                    let gauge = registry.register(metric.name, metric.help, raw::Gauge::default());
                    gauges.push((gauge, metric.read));
                }
                Kind::Counter => {
                    let counter =
                        registry.register(metric.name, metric.help, raw::Counter::default());
                    counters.push((counter, metric.read));
                }
            }
        }
        let mut metrics = Self { gauges, counters };
        metrics.update();
        Some(metrics)
    }

    /// Reads the current statistics into the metrics.
    pub fn update(&mut self) {
        let Some(stats) = Stats::read() else {
            return;
        };
        for (gauge, read) in &self.gauges {
            let _ = gauge.try_set(read(&stats));
        }
        for (counter, read) in &self.counters {
            counter.inner().fetch_max(read(&stats), Ordering::Relaxed);
        }
    }
}
