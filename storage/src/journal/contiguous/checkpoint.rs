//! A small durable record that recovery reads before trusting anything on disk.
//!
//! A journal's contents are mostly recovered from its blobs: blob indexes give positions and
//! blob lengths give item counts. Recovery walks the blobs from oldest to newest and stops at
//! the first one that is missing or too short, since everything after a gap is unreachable.
//! The [Checkpoint] records the three facts that blob state alone cannot provide:
//!
//! - The pruning boundary, when it falls mid-blob (from
//!   [Journal::init_at_size](super::fixed::Journal::init_at_size)): recovery needs the exact
//!   position where the oldest blob's items begin.
//! - The recovery watermark: a floor on the journal size that external consumers (such as the
//!   [variable journal](super::variable::Journal), which indexes its data with a fixed journal)
//!   have durably recorded. Items below the watermark must survive a crash; items above it may
//!   be replayed or discarded.
//! - The clear target, while a clear/reset is in progress: the target is recorded before any
//!   blob is deleted, so a crash mid-clear is finished on reopen instead of being misread as
//!   corruption.
//!
//! # Invariants
//!
//! [Checkpoint] is a passive store; the journal upholds these by ordering its calls:
//!
//! - An entry advances only after the blob state it describes is durable.
//! - An entry is lowered before blob state moves backward (rewind, clear).
//!
//! Together they keep the checkpoint a safe under-estimate of what is on disk: recovery may find
//! more durable data than the checkpoint claims, never less.

use crate::{
    journal::Error,
    metadata::{Config as MetadataConfig, Metadata},
    Context,
};
use commonware_utils::sequence::VecU64;

/// Key for the mid-blob pruning boundary. Absent when the boundary is blob-aligned (it is then
/// derived from the oldest blob).
const PRUNING_BOUNDARY_KEY: u64 = 1;

/// Key for the target of an in-progress clear.
const CLEAR_TARGET_KEY: u64 = 2;

/// Key for the recovery watermark.
const RECOVERY_WATERMARK_KEY: u64 = 3;

/// The journal's durable recovery checkpoint.
pub(crate) struct Checkpoint<E: Context> {
    metadata: Metadata<E, u64, VecU64>,
}

impl<E: Context> Checkpoint<E> {
    /// Open the checkpoint stored in `{partition_prefix}-metadata`.
    pub(super) async fn open(context: E, partition_prefix: &str) -> Result<Self, Error> {
        let metadata = Metadata::<_, u64, VecU64>::init(
            context,
            MetadataConfig {
                partition: format!("{partition_prefix}-metadata"),
                codec_config: (),
            },
        )
        .await?;
        Ok(Self { metadata })
    }

    /// Read a `u64`-valued entry, if present.
    fn get(&self, key: u64) -> Option<u64> {
        self.metadata.get(&key).copied().map(u64::from)
    }

    /// The recovery watermark, if one has been recorded.
    pub(super) fn watermark(&self) -> Option<u64> {
        self.get(RECOVERY_WATERMARK_KEY)
    }

    /// The recorded mid-blob pruning boundary, if any.
    pub(super) fn boundary_hint(&self) -> Option<u64> {
        self.get(PRUNING_BOUNDARY_KEY)
    }

    /// The target of an in-progress clear, if one was staged.
    pub(super) fn clear_target(&self) -> Option<u64> {
        self.get(CLEAR_TARGET_KEY)
    }

    /// Durably record the boundary and watermark, writing only entries that changed.
    pub(super) async fn persist(
        &mut self,
        items_per_blob: u64,
        boundary: u64,
        watermark: u64,
    ) -> Result<(), Error> {
        // A blob-aligned boundary is derived from the oldest blob, so the entry is only kept
        // while the boundary is mid-blob.
        if boundary.is_multiple_of(items_per_blob) {
            if self.boundary_hint().is_some() {
                self.metadata.remove(&PRUNING_BOUNDARY_KEY);
            }
        } else if self.boundary_hint() != Some(boundary) {
            self.metadata.put(PRUNING_BOUNDARY_KEY, boundary.into());
        }
        if self.watermark() != Some(watermark) {
            self.metadata.put(RECOVERY_WATERMARK_KEY, watermark.into());
        }
        // Always sync, even if this call staged nothing: `lower_watermark` stages without syncing,
        // so skipping the sync when our own entries are unchanged could drop that pending change.
        self.sync().await
    }

    /// Lower the watermark to at most `limit`, returning whether it changed. Called before
    /// blob state moves backward so the persisted watermark never exceeds surviving data.
    /// The caller syncs.
    pub(super) fn lower_watermark(&mut self, limit: u64) -> bool {
        match self.watermark() {
            Some(current) if current > limit => {
                self.metadata.put(RECOVERY_WATERMARK_KEY, limit.into());
                true
            }
            _ => false,
        }
    }

    /// Durably record the intent to clear to `target`, lowering the watermark first.
    pub(super) async fn stage_clear(&mut self, target: u64) -> Result<(), Error> {
        self.lower_watermark(target);
        self.metadata.put(CLEAR_TARGET_KEY, target.into());
        self.sync().await
    }

    /// Durably complete a clear to `target`: drop the intent and record `target` as both the
    /// boundary and the watermark.
    pub(super) async fn finish_clear(
        &mut self,
        items_per_blob: u64,
        target: u64,
    ) -> Result<(), Error> {
        self.metadata.remove(&CLEAR_TARGET_KEY);
        self.persist(items_per_blob, target, target).await
    }

    /// Make staged entries durable.
    pub(super) async fn sync(&mut self) -> Result<(), Error> {
        self.metadata.sync().await?;
        Ok(())
    }

    /// Remove the checkpoint's partition.
    pub(super) async fn destroy(self) -> Result<(), Error> {
        self.metadata.destroy().await?;
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::test_traced;
    use commonware_runtime::{deterministic, Runner as _, Supervisor as _};

    /// Direct-injection helpers used by tests (here and in the fixed journal) to plant states
    /// the production API never produces: invalid or absent watermarks, a corrupt clear intent,
    /// or wiped metadata.
    impl<E: Context> Checkpoint<E> {
        /// Set the watermark directly, or remove it with `None` (simulating a legacy journal).
        pub(crate) fn set_watermark(&mut self, watermark: Option<u64>) {
            match watermark {
                Some(watermark) => {
                    self.metadata.put(RECOVERY_WATERMARK_KEY, watermark.into());
                }
                None => {
                    self.metadata.remove(&RECOVERY_WATERMARK_KEY);
                }
            }
        }

        /// Set the mid-blob pruning boundary directly.
        pub(crate) fn set_boundary_hint(&mut self, boundary: u64) {
            self.metadata.put(PRUNING_BOUNDARY_KEY, boundary.into());
        }

        /// Stage a clear intent directly.
        pub(crate) fn set_clear_target(&mut self, target: u64) {
            self.metadata.put(CLEAR_TARGET_KEY, target.into());
        }

        /// Remove every entry, simulating metadata corruption.
        pub(crate) fn clear(&mut self) {
            self.metadata.clear();
        }
    }

    #[test_traced]
    fn test_lower_watermark_only_lowers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut checkpoint = Checkpoint::open(context, "lw").await.unwrap();

            // No watermark recorded yet: nothing to lower.
            assert!(!checkpoint.lower_watermark(5));
            assert_eq!(checkpoint.watermark(), None);

            checkpoint.persist(10, 0, 8).await.unwrap();
            // Equal and higher limits are not lowerings.
            assert!(!checkpoint.lower_watermark(8));
            assert!(!checkpoint.lower_watermark(12));
            assert_eq!(checkpoint.watermark(), Some(8));
            // A strictly lower limit lowers.
            assert!(checkpoint.lower_watermark(3));
            assert_eq!(checkpoint.watermark(), Some(3));
        });
    }

    #[test_traced]
    fn test_persist_round_trips_across_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            {
                let mut checkpoint = Checkpoint::open(context.child("a"), "rt").await.unwrap();
                // A mid-blob boundary is kept; the watermark is recorded.
                checkpoint.persist(10, 13, 25).await.unwrap();
            }
            let checkpoint = Checkpoint::open(context.child("b"), "rt").await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), Some(13));
            assert_eq!(checkpoint.watermark(), Some(25));
            assert_eq!(checkpoint.clear_target(), None);
        });
    }

    #[test_traced]
    fn test_persist_boundary_hint_tracks_alignment() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut checkpoint = Checkpoint::open(context, "align").await.unwrap();

            // A mid-blob boundary is recorded as a hint.
            checkpoint.persist(10, 13, 0).await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), Some(13));

            // A later blob-aligned boundary drops the stale hint (it is derived from the
            // oldest blob).
            checkpoint.persist(10, 20, 0).await.unwrap();
            assert_eq!(checkpoint.boundary_hint(), None);
        });
    }

    #[test_traced]
    fn test_clear_lifecycle_survives_crash() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            {
                let mut checkpoint = Checkpoint::open(context.child("a"), "clear").await.unwrap();
                checkpoint.persist(10, 0, 30).await.unwrap();
                // Staging records the intent and lowers the watermark to the target.
                checkpoint.stage_clear(20).await.unwrap();
                assert_eq!(checkpoint.clear_target(), Some(20));
                assert_eq!(checkpoint.watermark(), Some(20));
            }
            // A crash after staging leaves the intent durable.
            {
                let mut checkpoint = Checkpoint::open(context.child("b"), "clear").await.unwrap();
                assert_eq!(checkpoint.clear_target(), Some(20));
                // Completing drops the intent and records the target as boundary and watermark.
                checkpoint.finish_clear(10, 20).await.unwrap();
            }
            let checkpoint = Checkpoint::open(context.child("c"), "clear").await.unwrap();
            assert_eq!(checkpoint.clear_target(), None);
            assert_eq!(checkpoint.watermark(), Some(20));
            // 20 is blob-aligned, so no hint is retained.
            assert_eq!(checkpoint.boundary_hint(), None);
        });
    }

    #[test_traced]
    fn test_stage_clear_does_not_raise_watermark() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut checkpoint = Checkpoint::open(context, "sc").await.unwrap();
            checkpoint.persist(10, 0, 5).await.unwrap();

            // Target above the current watermark: the intent is recorded but the watermark holds.
            checkpoint.stage_clear(9).await.unwrap();
            assert_eq!(checkpoint.clear_target(), Some(9));
            assert_eq!(checkpoint.watermark(), Some(5));
        });
    }
}
