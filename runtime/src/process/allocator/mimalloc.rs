//! Metrics collected from mimalloc.
//!
//! The family is registered only when the process's global allocator is
//! [`commonware_allocator::mimalloc::MiMalloc`], installed directly or
//! wrapped by another allocator. Counters are raised to the cumulative value
//! read from each [`Stats`] snapshot.

use crate::telemetry::metrics::{Counter, Gauge, GaugeExt, Register, raw};
use commonware_allocator::mimalloc::{
    self, Stats,
    metrics::{Kind, METRICS},
};
use std::sync::{LazyLock, atomic::Ordering};
use tracing::warn;

/// Whether allocations reach the linked mimalloc, the one [`Stats`] reads.
///
/// A probe allocation lands in mimalloc's heap region exactly when allocations
/// reach it, whichever wrapper installed mimalloc as the global allocator. The
/// global allocator is fixed for the life of the process, so one probe
/// suffices. Every runtime constructs these metrics, so the warning is logged
/// once per process.
static GLOBAL_IS_MIMALLOC: LazyLock<bool> = LazyLock::new(|| {
    let global = mimalloc::is_global_allocator();
    if !global {
        warn!("mimalloc metrics enabled but mimalloc is not the global allocator");
    }
    global
});

/// Reads one statistic from a snapshot.
type Read = fn(&Stats) -> u64;

/// The registered series, each with the statistic that feeds it.
pub struct Metrics {
    gauges: Vec<(Gauge, Read)>,
    counters: Vec<(Counter, Read)>,
}

impl Metrics {
    /// Registers the allocator family if mimalloc is the global allocator.
    /// Otherwise returns `None`, and the first call in the process logs a
    /// warning.
    pub fn init(registry: &mut impl Register) -> Option<Self> {
        if !*GLOBAL_IS_MIMALLOC {
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
