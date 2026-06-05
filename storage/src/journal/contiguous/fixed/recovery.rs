//! Turns disk state into journal state. This is the trust boundary: untrusted on-disk blob
//! lengths are reconciled against trusted metadata, and the bounds returned are proven (dense,
//! chunk-exact, watermark at most size) for the rest of the journal to rely on.

use super::{Config, Journal};
use crate::journal::contiguous::{
    blobs::{Blobs, Partition},
    snapshot::first_in_blob,
};
use crate::{
    journal::{contiguous::metrics::FixedMetrics as Metrics, Error},
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

/// A deferred repair to apply after metadata is persisted during init: `blob` becomes the new
/// tail, truncated to `truncate_to` bytes, and every blob strictly newer is removed.
pub(super) struct RecoveryRepair {
    pub(super) blob: u64,
    pub(super) truncate_to: u64,
}

impl<E: Context, A: CodecFixedShared> Journal<E, A> {
    /// Finish initialization using an already-open metadata handle. Callers use this after
    /// `open_metadata` so the metadata partition is opened exactly once.
    pub(super) async fn init_with_metadata(
        context: E,
        cfg: Config,
        mut metadata: Metadata<E, u64, VecU64>,
    ) -> Result<Self, Error> {
        let items_per_blob = cfg.items_per_blob.get();

        // A staged clear intent means all old blob data is about to be discarded. Honor it before
        // scanning or opening blobs so corrupt stale blobs cannot block recovery of the reset.
        if let Some(clear_target) = metadata.get(&CLEAR_TARGET_KEY).copied().map(u64::from) {
            return Self::complete_staged_clear(context, cfg, metadata, clear_target).await;
        }

        let blob_partition = Self::select_blob_partition(&context, &cfg).await?;
        let partition = Partition::new(
            context.child("blobs"),
            blob_partition,
            cfg.page_cache,
            cfg.write_buffer,
        );
        let mut pending = partition.open_all().await?;

        // Truncate any trailing non-chunk-aligned bytes on every blob before recovery. Items
        // are fixed size, so a blob ending in fewer than `CHUNK_SIZE` trailing bytes is junk
        // from an incomplete write (the page-CRC layer surfaces it as a partial logical tail).
        // The truncation is synced before `recover_bounds` queries lengths.
        for (&blob, writer) in &pending {
            let size = writer.size().await;
            if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
                let valid_size = size - (size % Self::CHUNK_SIZE_U64);
                warn!(
                    blob,
                    invalid_size = size,
                    new_size = valid_size,
                    "trailing bytes detected: truncating"
                );
                writer.resize(valid_size).await.map_err(Error::Runtime)?;
                writer.sync().await.map_err(Error::Runtime)?;
            }
        }

        let meta_pruning_boundary = metadata.get(&PRUNING_BOUNDARY_KEY).copied().map(u64::from);
        let meta_recovery_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from);

        let (pruning_boundary, size, recovery_watermark, repair) = Self::recover_bounds(
            &pending,
            items_per_blob,
            meta_pruning_boundary,
            meta_recovery_watermark,
        )
        .await?;

        // Persist any lowered checkpoint before applying blob repairs that move recovered state
        // backward.
        Self::persist_metadata_entries_raw(
            &mut metadata,
            items_per_blob,
            pruning_boundary,
            recovery_watermark,
        )
        .await?;

        // Apply repair (if any). The repair blob becomes the new tail; blobs strictly newer
        // than it are removed (newest-first) and the repair truncation is synced, so the repair
        // is durable before sealing.
        let tail_blob = size / items_per_blob;
        if let Some(repair) = repair {
            if repair.blob != tail_blob {
                return Err(Error::Corruption(format!(
                    "recovery repair target {} != tail blob {tail_blob}",
                    repair.blob
                )));
            }
            while let Some((&newest, _)) = pending.last_key_value() {
                if newest <= repair.blob {
                    break;
                }
                drop(pending.remove(&newest));
                partition.remove(newest).await?;
            }
            if let Some(writer) = pending.get(&repair.blob) {
                if repair.truncate_to < writer.size().await {
                    writer
                        .resize(repair.truncate_to)
                        .await
                        .map_err(Error::Runtime)?;
                    writer.sync().await.map_err(Error::Runtime)?;
                }
            }
        }

        // Seal every blob below the tail and assemble the run.
        let blobs = Blobs::recover(partition, pending, tail_blob).await?;

        // Bytes beyond the persisted recovery watermark may be readable after reopen without
        // being crash-durable, so the next commit/sync must force a data sync before advancing it.
        let dirty_from_blob =
            (recovery_watermark < size).then_some(recovery_watermark / items_per_blob);

        let metrics = Metrics::new(context);
        metrics.update(size, pruning_boundary, items_per_blob);

        Ok(Self::from_blobs(
            blobs,
            metadata,
            size,
            pruning_boundary,
            dirty_from_blob,
            cfg.items_per_blob,
            metrics,
        ))
    }

    /// Complete an interrupted clear: discard all blob partitions and start fresh at
    /// `clear_target`, then finalize the metadata the crashed clear left staged.
    async fn complete_staged_clear(
        context: E,
        cfg: Config,
        mut metadata: Metadata<E, u64, VecU64>,
        clear_target: u64,
    ) -> Result<Self, Error> {
        warn!(clear_target, "crash repair: completing interrupted clear");
        let items_per_blob = cfg.items_per_blob.get();
        let new_partition = format!("{}-blobs", cfg.partition);
        Self::remove_blob_partition(&context, &cfg.partition).await?;
        Self::remove_blob_partition(&context, &new_partition).await?;
        let tail_blob = clear_target / items_per_blob;
        let partition = Partition::new(
            context.child("blobs"),
            new_partition,
            cfg.page_cache,
            cfg.write_buffer,
        );
        let blobs = Blobs::recover(partition, BTreeMap::new(), tail_blob).await?;
        Self::stage_pruning_boundary_metadata(&mut metadata, items_per_blob, clear_target);
        metadata.put(RECOVERY_WATERMARK_KEY, clear_target.into());
        metadata.remove(&CLEAR_TARGET_KEY);
        metadata.sync().await?;

        let metrics = Metrics::new(context);
        metrics.update(clear_target, clear_target, items_per_blob);
        Ok(Self::from_blobs(
            blobs,
            metadata,
            clear_target,
            clear_target,
            None,
            cfg.items_per_blob,
            metrics,
        ))
    }

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
    pub(super) fn lower_recovery_watermark(
        metadata: &mut Metadata<E, u64, VecU64>,
        limit: u64,
    ) -> bool {
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
    pub(super) async fn scan_partition(
        context: &E,
        partition: &str,
    ) -> Result<Vec<Vec<u8>>, Error> {
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

    /// Classify a blob's untrusted on-disk length against its logical capacity. A missing
    /// blob has zero length: that is what makes it a detectable gap.
    async fn classify_fill(
        pending: &BTreeMap<u64, Writer<E::Blob>>,
        items_per_blob: u64,
        pruning_boundary: u64,
        blob: u64,
    ) -> Result<BlobFill, Error> {
        let len = match pending.get(&blob) {
            Some(writer) => writer.size().await,
            None => 0,
        } / Self::CHUNK_SIZE_U64;
        let capacity = blob_capacity(pruning_boundary, blob, items_per_blob)?;
        Ok(match len.cmp(&capacity) {
            std::cmp::Ordering::Less => BlobFill::Short { len },
            std::cmp::Ordering::Equal => BlobFill::Full { len },
            std::cmp::Ordering::Greater => BlobFill::Overfull { len, capacity },
        })
    }

    /// Recover logical size by walking blob lengths from oldest to newest, truncating at the
    /// first short or missing non-tail blob.
    ///
    /// `pruning_boundary` is trusted (already reconciled by `recover_pruning_boundary`); blob
    /// lengths are untrusted disk state. The returned size is chunk-exact and the retained
    /// prefix is dense.
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
            let fill =
                Self::classify_fill(pending, items_per_blob, pruning_boundary, blob).await?;
            match fill {
                // Complete: count its items and keep walking.
                BlobFill::Full { len } => {
                    size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
                }
                // The newest blob is the append frontier; short is normal.
                BlobFill::Short { len } if blob == newest => {
                    size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
                    return Ok((size, None));
                }
                // A short or missing interior blob is a gap in durable data: everything newer
                // is unreachable. Truncate the run here.
                BlobFill::Short { len } => {
                    size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
                    return Ok((
                        size,
                        Some(RecoveryRepair {
                            blob,
                            truncate_to: Self::items_to_bytes(len)?,
                        }),
                    ));
                }
                BlobFill::Overfull { len, capacity } => {
                    return Err(Error::Corruption(format!(
                        "blob {blob} has too many items: expected at most {capacity}, got {len}"
                    )));
                }
            }
        }

        Ok((size, None))
    }
}

/// How a blob's on-disk item count compares to its logical capacity.
enum BlobFill {
    Full { len: u64 },
    Short { len: u64 },
    Overfull { len: u64, capacity: u64 },
}
