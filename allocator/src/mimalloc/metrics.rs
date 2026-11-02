//! Allocator statistics exported as metrics.
//!
//! [`METRICS`] names each exported [`Stats`] field with its help text and kind,
//! so a runtime can register every series by iterating it. The statistics are
//! process-wide, so every collector in a process reports the same values.

use super::Stats;

/// How a statistic behaves over time.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Kind {
    /// A value that rises and falls.
    Gauge,
    /// A cumulative total that only rises.
    Counter,
}

/// One exported statistic.
#[derive(Clone, Copy, Debug)]
pub struct Metric {
    /// Metric name, without any family prefix.
    pub name: &'static str,
    /// Help text.
    pub help: &'static str,
    /// Gauge or counter.
    pub kind: Kind,
    /// Reads the value from a snapshot.
    pub read: fn(&Stats) -> u64,
}

/// The exported statistics.
pub const METRICS: [Metric; 13] = [
    Metric {
        name: "reserved_bytes",
        help: "Bytes the allocator reserved from the operating system",
        kind: Kind::Gauge,
        read: |stats| stats.reserved_bytes,
    },
    Metric {
        name: "pinned_bytes",
        help: "Bytes of pinned reservations the allocator never purges",
        kind: Kind::Gauge,
        read: |stats| stats.pinned_bytes,
    },
    Metric {
        name: "committed_bytes",
        help: "Bytes the allocator currently has committed",
        kind: Kind::Gauge,
        read: |stats| stats.committed_bytes,
    },
    Metric {
        name: "committed_peak_bytes",
        help: "Peak bytes the allocator has had committed",
        kind: Kind::Gauge,
        read: |stats| stats.committed_peak_bytes,
    },
    Metric {
        name: "allocated_bytes",
        help: "Bytes handed out to callers, as of each thread's last statistics merge",
        kind: Kind::Gauge,
        read: |stats| stats.allocated_bytes,
    },
    Metric {
        name: "pages",
        help: "Allocator pages currently in use",
        kind: Kind::Gauge,
        read: |stats| stats.pages,
    },
    Metric {
        name: "threads",
        help: "Threads currently known to the allocator",
        kind: Kind::Gauge,
        read: |stats| stats.threads,
    },
    Metric {
        name: "arenas",
        help: "Arenas currently managed by the allocator",
        kind: Kind::Gauge,
        read: |stats| stats.arenas,
    },
    Metric {
        name: "purged_bytes",
        help: "Total bytes the allocator purged back to the operating system",
        kind: Kind::Counter,
        read: |stats| stats.purged_bytes,
    },
    Metric {
        name: "purge_calls",
        help: "Total purge operations performed by the allocator",
        kind: Kind::Counter,
        read: |stats| stats.purge_calls,
    },
    Metric {
        name: "mmap_calls",
        help: "Total memory mappings the allocator requested from the operating system",
        kind: Kind::Counter,
        read: |stats| stats.mmap_calls,
    },
    Metric {
        name: "huge_allocations",
        help: "Total allocations larger than the allocator's largest size class",
        kind: Kind::Counter,
        read: |stats| stats.huge_allocations,
    },
    Metric {
        name: "huge_bytes",
        help: "Total bytes of allocations larger than the allocator's largest size class",
        kind: Kind::Counter,
        read: |stats| stats.huge_bytes,
    },
];
