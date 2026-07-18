//! Operational metrics for the volume.
//!
//! The volume sits BELOW the metered storage wrapper, so caller-level
//! operation counts live there; these metrics expose what only the volume
//! can see: physical commits and their coalescing ratio, inner fsync
//! latency, recovery outcomes, corruption detections, copy-on-write churn,
//! and the volume file's space accounting (the file never shrinks, so the
//! free/pending-free split is the only early warning before disk
//! exhaustion).

use super::core::State;
use crate::telemetry::metrics::{
    histogram::Buckets, raw, Counter, Gauge, GaugeExt as _, Histogram, Register, Registered,
    Registration,
};

/// Registered volume metrics (or inert unregistered handles when the
/// volume is constructed without a registry).
pub(super) struct Metrics {
    /// Confirmed commits (each ends in one inner fsync).
    pub commits: Counter,
    /// Durability requests served by commits: syncs, started syncs, batch
    /// commits (immediate and started), blob creations, and removals.
    /// `sync_requests / commits` is the coalescing ratio.
    pub sync_requests: Counter,
    /// Inner fsync latency in seconds. Never observed on wasm32, which has
    /// no monotonic clock.
    #[cfg_attr(target_arch = "wasm32", allow(dead_code))]
    pub fsync_duration: Histogram,
    /// Successful recoveries (volume opens).
    pub recoveries: Counter,
    /// Recoveries that rejected the newest commit and fell back one commit
    /// (a torn unacknowledged commit, or bit rot in the newest commit's
    /// metadata).
    pub recovery_fallbacks: Counter,
    /// Seq of the most recently rolled-back newest commit.
    pub rolled_back_seq: Gauge,
    /// Checksum-verification failures surfaced as corruption errors.
    pub corruptions: Counter,
    /// Bytes rewritten through copy-on-write relocation (the freeze rule).
    pub cow_bytes: Counter,
    /// High-water mark of the volume file's allocated span in bytes.
    /// Monotonic while the volume is open: freeing an extent at the span's
    /// end lowers the allocator's end, never this gauge or the file itself
    /// (recovery rebaselines it from the adopted table).
    pub file_end_bytes: Gauge,
    /// Free bytes below the high-water mark (reusable for new extents).
    pub free_bytes: Gauge,
    /// Bytes queued for reuse but not yet released: waiting on a
    /// confirming commit, or pinned by open handles to removed blobs.
    pub pending_free_bytes: Gauge,
    /// Blobs holding hydrated in-RAM state.
    pub open_blobs: Gauge,
    /// Blobs known only by their committed table entry.
    pub dormant_blobs: Gauge,
    /// 1 once the poison latch fired: every storage operation fails until
    /// restart.
    pub poisoned: Gauge,
}

impl Metrics {
    /// Register the volume's metrics under `registry` (prefixed
    /// `storage_volume`).
    pub fn new(registry: &mut impl Register) -> Self {
        let mut registry = registry.sub_registry("storage_volume");
        Self {
            commits: registry.register(
                "commits",
                "Confirmed volume commits (one inner fsync each)",
                raw::Counter::default(),
            ),
            sync_requests: registry.register(
                "sync_requests",
                "Durability requests served by volume commits",
                raw::Counter::default(),
            ),
            fsync_duration: registry.register(
                "fsync_duration",
                "Inner fsync latency in seconds",
                raw::Histogram::new(Buckets::LOCAL),
            ),
            recoveries: registry.register(
                "recoveries",
                "Successful volume recoveries",
                raw::Counter::default(),
            ),
            recovery_fallbacks: registry.register(
                "recovery_fallbacks",
                "Recoveries that rolled back the newest commit",
                raw::Counter::default(),
            ),
            rolled_back_seq: registry.register(
                "rolled_back_seq",
                "Seq of the most recently rolled-back newest commit",
                raw::Gauge::default(),
            ),
            corruptions: registry.register(
                "corruptions",
                "Checksum verification failures surfaced as corruption",
                raw::Counter::default(),
            ),
            cow_bytes: registry.register(
                "cow_bytes",
                "Bytes rewritten through copy-on-write relocation",
                raw::Counter::default(),
            ),
            file_end_bytes: registry.register(
                "file_end_bytes",
                "High-water mark of the volume file's allocated span in bytes",
                raw::Gauge::default(),
            ),
            free_bytes: registry.register(
                "free_bytes",
                "Free bytes below the volume file's high-water mark",
                raw::Gauge::default(),
            ),
            pending_free_bytes: registry.register(
                "pending_free_bytes",
                "Bytes queued for reuse but not yet released",
                raw::Gauge::default(),
            ),
            open_blobs: registry.register(
                "open_blobs",
                "Blobs holding hydrated in-RAM state",
                raw::Gauge::default(),
            ),
            dormant_blobs: registry.register(
                "dormant_blobs",
                "Blobs known only by their committed table entry",
                raw::Gauge::default(),
            ),
            poisoned: registry.register(
                "poisoned",
                "1 once the poison latch fired (all storage fails until restart)",
                raw::Gauge::default(),
            ),
        }
    }

    /// Inert handles exposed by no registry, for volumes constructed
    /// without one (see `Storage::new`).
    pub fn unregistered() -> Self {
        fn inert<M: Default>() -> Registered<M> {
            Registered::with_registration(M::default(), Registration::from(()))
        }
        Self {
            commits: inert(),
            sync_requests: inert(),
            fsync_duration: Registered::with_registration(
                raw::Histogram::new(Buckets::LOCAL),
                Registration::from(()),
            ),
            recoveries: inert(),
            recovery_fallbacks: inert(),
            rolled_back_seq: inert(),
            corruptions: inert(),
            cow_bytes: inert(),
            file_end_bytes: inert(),
            free_bytes: inert(),
            pending_free_bytes: inert(),
            open_blobs: inert(),
            dormant_blobs: inert(),
            poisoned: inert(),
        }
    }

    /// Refresh the space and namespace gauges from `state` (called at
    /// commit finalize, deferred-free application, and recovery), raising
    /// its file high-water mark first so the gauge never decreases while
    /// the volume is open.
    pub fn observe_state(&self, state: &mut State) {
        state.file_high_water = state.file_high_water.max(state.alloc.end());
        let _ = self.file_end_bytes.try_set(state.file_high_water);
        let _ = self.free_bytes.try_set(state.alloc.free_bytes());
        let pending: u64 = state.pending_free.iter().map(|(e, _, _)| e.len).sum();
        let _ = self.pending_free_bytes.try_set(pending);
        let _ = self.open_blobs.try_set(state.open.len());
        let _ = self.dormant_blobs.try_set(state.dormant.len());
    }
}
