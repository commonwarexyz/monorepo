//! Turns disk state into journal state: bounds recovery, repair, and metadata reconciliation.

use super::{first_in_blob, Config, Journal};
use crate::{
    journal::Error,
    metadata::{Config as MetadataConfig, Metadata},
    Context,
};
use commonware_codec::CodecFixedShared;
use commonware_runtime::{buffer::paged::Writer, Error as RuntimeError};
use commonware_utils::sequence::VecU64;
use std::collections::BTreeMap;
use tracing::warn;

/// Metadata key for a mid-blob pruning boundary.
///
/// This key is present only when the oldest retained item is not blob-aligned. It is persisted
/// after the blob state it describes exists. Recovery trusts it when it matches the oldest retained
/// blob, falls back to the blob boundary when it lags (crash before metadata update), and
/// returns corruption when it is ahead of blob state or no blobs exist.
pub(super) const PRUNING_BOUNDARY_KEY: u64 = 1;

/// Metadata key for an in-progress clear/reset target.
///
/// This key is synced before destructive reset work starts. If recovery sees it, recovery
/// completes the reset to the recorded target before normal bounds recovery.
pub(crate) const CLEAR_TARGET_KEY: u64 = 2;

/// Metadata key for storing the recovery watermark.
pub(super) const RECOVERY_WATERMARK_KEY: u64 = 3;

/// Maximum number of items a blob can physically hold. This is `items_per_blob` unless
/// the pruning boundary falls mid-blob (from `init_at_size`), in which case the skipped prefix
/// reduces the capacity.
#[inline]
fn blob_capacity(pruning_boundary: u64, blob: u64, items_per_blob: u64) -> Result<u64, Error> {
    let start = blob
        .checked_mul(items_per_blob)
        .ok_or(Error::OffsetOverflow)?;
    let skipped = pruning_boundary.saturating_sub(start).min(items_per_blob);
    Ok(items_per_blob - skipped)
}

/// A deferred blob truncation to apply after metadata is persisted during init.
pub(super) struct RecoveryRepair {
    pub(super) blob: u64,
    pub(super) byte_offset: u64,
}

impl<E: Context, A: CodecFixedShared> Journal<E, A> {
    /// Stage pruning-boundary and recovery-watermark entries into `metadata`'s in-memory state.
    ///
    /// Only writes when a value actually changes. The caller is responsible for syncing.
    pub(super) fn stage_metadata_entries(
        metadata: &mut Metadata<E, u64, VecU64>,
        items_per_blob: u64,
        pruning_boundary: u64,
        recovery_watermark: u64,
    ) {
        let current_pruning = metadata.get(&PRUNING_BOUNDARY_KEY).copied().map(u64::from);
        if !pruning_boundary.is_multiple_of(items_per_blob) {
            if current_pruning != Some(pruning_boundary) {
                metadata.put(PRUNING_BOUNDARY_KEY, pruning_boundary.into());
            }
        } else if current_pruning.is_some() {
            metadata.remove(&PRUNING_BOUNDARY_KEY);
        }

        let current_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from);
        if current_watermark != Some(recovery_watermark) {
            metadata.put(RECOVERY_WATERMARK_KEY, recovery_watermark.into());
        }
    }

    /// Stage a recovery watermark no greater than `limit`.
    ///
    /// This is used before blob state moves backward so external consumers never see a persisted
    /// recovery checkpoint beyond the rewind/clear target.
    pub(super) fn lower_recovery_watermark(metadata: &mut Metadata<E, u64, VecU64>, limit: u64) -> bool {
        let Some(current) = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
        else {
            return false;
        };
        if current <= limit {
            return false;
        }
        metadata.put(RECOVERY_WATERMARK_KEY, limit.into());
        true
    }

    /// Stage a recovery-watermark entry no greater than `limit` in raw metadata.
    ///
    /// This is used by `init_at_size` before it clears existing blobs, before a `Journal` exists.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) fn update_metadata_watermark_before_clear(
        metadata: &mut Metadata<E, u64, VecU64>,
        limit: u64,
    ) -> bool {
        Self::lower_recovery_watermark(metadata, limit)
    }

    /// Open the metadata partition for `cfg`.
    pub(crate) async fn open_metadata(
        context: E,
        cfg: &Config,
    ) -> Result<Metadata<E, u64, VecU64>, Error> {
        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        Ok(Metadata::<_, u64, VecU64>::init(context, meta_cfg).await?)
    }

    /// Scan a partition and return blob names, treating a missing partition as empty.
    pub(super) async fn scan_partition(context: &E, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        match context.scan(partition).await {
            Ok(blobs) => Ok(blobs),
            Err(RuntimeError::PartitionMissing(_)) => Ok(Vec::new()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Remove a blob partition before completing a staged clear intent.
    pub(super) async fn remove_blob_partition(context: &E, partition: &str) -> Result<(), Error> {
        match context.remove(partition, None).await {
            Ok(()) | Err(RuntimeError::PartitionMissing(_)) => Ok(()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Select the blobs partition using legacy-first compatibility rules.
    ///
    /// If both legacy and new blobs partitions contain data, returns corruption.
    /// If neither contains data, defaults to the new blobs partition.
    // TODO(#2941): Remove legacy partition support
    pub(super) async fn select_blob_partition(context: &E, cfg: &Config) -> Result<String, Error> {
        let legacy_partition = cfg.partition.as_str();
        let new_partition = format!("{}-blobs", cfg.partition);

        let legacy_blobs = Self::scan_partition(context, legacy_partition).await?;
        let new_blobs = Self::scan_partition(context, &new_partition).await?;

        if !legacy_blobs.is_empty() && !new_blobs.is_empty() {
            return Err(Error::Corruption(format!(
                "both legacy and blobs partitions contain data: legacy={} blobs={}",
                legacy_partition, new_partition
            )));
        }

        if !legacy_blobs.is_empty() {
            Ok(legacy_partition.into())
        } else {
            Ok(new_partition)
        }
    }

    /// Stage `PRUNING_BOUNDARY_KEY` in metadata, putting the mid-blob boundary or removing the
    /// entry when blob-aligned.
    pub(super) fn stage_pruning_boundary_metadata(
        metadata: &mut Metadata<E, u64, VecU64>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) {
        if !pruning_boundary.is_multiple_of(items_per_blob) {
            metadata.put(PRUNING_BOUNDARY_KEY, pruning_boundary.into());
        } else {
            metadata.remove(&PRUNING_BOUNDARY_KEY);
        }
    }

    /// Stage pruning-boundary and recovery-watermark entries directly into raw metadata and
    /// persist them. Used by [`Self::init`] before constructing the journal.
    pub(super) async fn persist_metadata_entries_raw(
        metadata: &mut Metadata<E, u64, VecU64>,
        items_per_blob: u64,
        pruning_boundary: u64,
        recovery_watermark: u64,
    ) -> Result<(), Error> {
        Self::stage_metadata_entries(
            metadata,
            items_per_blob,
            pruning_boundary,
            recovery_watermark,
        );
        metadata.sync().await?;
        Ok(())
    }

    /// Recover `(pruning_boundary, size, recovery_watermark, repair)` from metadata and blob state.
    ///
    /// Pruning metadata that lags blob state is repaired from the blob boundary; pruning metadata
    /// ahead of blob state or a watermark beyond the recovered size is corruption. The caller
    /// persists metadata before applying the returned repair (see comment at the call site).
    pub(super) async fn recover_bounds(
        pending: &BTreeMap<u64, Writer<E::Blob>>,
        items_per_blob: u64,
        meta_pruning_boundary: Option<u64>,
        meta_recovery_watermark: Option<u64>,
    ) -> Result<(u64, u64, u64, Option<RecoveryRepair>), Error> {
        let pruning_boundary = Self::recover_pruning_boundary(
            meta_pruning_boundary,
            pending.keys().next().copied(),
            items_per_blob,
        )?;

        let (size, repair) =
            Self::recover_by_walking_lengths(pending, items_per_blob, pruning_boundary).await?;

        let recovery_watermark = match meta_recovery_watermark {
            Some(watermark) if watermark > size => {
                // The dual-CRC page mechanism prevents losing previously-synced data, and
                // clear_to_size updates the watermark atomically via CLEAR_TARGET_KEY. A
                // watermark beyond the recoverable size indicates external corruption.
                return Err(Error::Corruption(format!(
                    "recovery watermark {watermark} exceeds recoverable size {size}"
                )));
            }
            Some(watermark) => watermark,
            None if repair.is_some() => {
                // A legacy journal with a short non-tail blob violates the old rollover-sync
                // invariant (each blob was fsynced before the next received writes).
                return Err(Error::Corruption(
                    "legacy journal has a short non-tail blob".into(),
                ));
            }
            // Legacy journals have no watermark. Under the old rollover-sync invariant, all
            // non-tail blobs are durable; only the tail may have unfsynced data.
            None => first_in_blob(pruning_boundary, size / items_per_blob, items_per_blob)?,
        };

        Ok((pruning_boundary, size, recovery_watermark, repair))
    }

    /// Recover the pruning boundary from metadata if it still matches the oldest retained blob.
    ///
    /// Missing or blob-aligned metadata means the blob boundary is authoritative. Mid-blob
    /// metadata is trusted only when it belongs to the current oldest blob.
    fn recover_pruning_boundary(
        meta_pruning_boundary: Option<u64>,
        oldest_blob: Option<u64>,
        items_per_blob: u64,
    ) -> Result<u64, Error> {
        let blob_boundary = match oldest_blob {
            Some(oldest) => oldest
                .checked_mul(items_per_blob)
                .ok_or(Error::OffsetOverflow)?,
            None => 0,
        };

        let Some(meta_pruning_boundary) = meta_pruning_boundary else {
            return Ok(blob_boundary);
        };
        if meta_pruning_boundary.is_multiple_of(items_per_blob) {
            return Ok(blob_boundary);
        }

        let meta_oldest_blob = meta_pruning_boundary / items_per_blob;
        match oldest_blob {
            Some(oldest_blob) if meta_oldest_blob == oldest_blob => Ok(meta_pruning_boundary),
            Some(oldest_blob) if meta_oldest_blob < oldest_blob => {
                warn!(
                    meta_oldest_blob,
                    oldest_blob, "crash repair: pruning metadata stale, computing from blobs"
                );
                Ok(blob_boundary)
            }
            Some(oldest_blob) => {
                // Metadata ahead of blob state should never arise: prune removes blobs before
                // sync persists metadata, and clear_to_size uses CLEAR_TARGET_KEY.
                Err(Error::Corruption(format!(
                    "pruning metadata references blob {meta_oldest_blob} \
                     but oldest blob is blob {oldest_blob}"
                )))
            }
            None => {
                // Mid-blob pruning metadata with no blobs should never arise:
                // complete_clear_to_size handles CLEAR_TARGET_KEY before we get here,
                // and no other operation removes all blobs without updating metadata.
                Err(Error::Corruption(format!(
                    "pruning metadata references blob {meta_oldest_blob} but no blobs exist"
                )))
            }
        }
    }

    async fn blob_len_within_capacity(
        pending: &BTreeMap<u64, Writer<E::Blob>>,
        items_per_blob: u64,
        pruning_boundary: u64,
        blob: u64,
    ) -> Result<(u64, u64), Error> {
        // A missing blob has zero length: that is what makes it a detectable gap.
        let len = match pending.get(&blob) {
            Some(writer) => writer.size().await,
            None => 0,
        } / Self::CHUNK_SIZE_U64;
        let capacity = blob_capacity(pruning_boundary, blob, items_per_blob)?;
        if len > capacity {
            return Err(Error::Corruption(format!(
                "blob {blob} has too many items: expected at most {capacity}, got {len}"
            )));
        }
        Ok((len, capacity))
    }

    /// Recover logical size by walking blob lengths from oldest to newest, truncating at the
    /// first short or missing non-tail blob.
    async fn recover_by_walking_lengths(
        pending: &BTreeMap<u64, Writer<E::Blob>>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) -> Result<(u64, Option<RecoveryRepair>), Error> {
        let oldest = pending.keys().next().copied();
        let newest = pending.keys().next_back().copied();

        let (Some(oldest), Some(newest)) = (oldest, newest) else {
            return Ok((pruning_boundary, None));
        };

        let mut size = pruning_boundary;
        for blob in oldest..=newest {
            let (len, capacity) =
                Self::blob_len_within_capacity(pending, items_per_blob, pruning_boundary, blob)
                    .await?;

            size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
            if len < capacity {
                if blob == newest {
                    return Ok((size, None));
                }
                return Ok((
                    size,
                    Some(RecoveryRepair {
                        blob,
                        byte_offset: len
                            .checked_mul(Self::CHUNK_SIZE_U64)
                            .ok_or(Error::OffsetOverflow)?,
                    }),
                ));
            }
        }

        Ok((size, None))
    }
}
