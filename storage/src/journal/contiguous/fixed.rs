//! An append-only log for storing fixed length _items_ on disk.
//!
//! In addition to replay, stored items can be fetched directly by their `position` in the journal,
//! where position is defined as the item's order of insertion starting from 0, unaffected by
//! pruning.
//!
//! _See [super::variable] for a journal that supports variable length items._
//!
//! # Format
//!
//! Data stored in a `fixed::Journal` is persisted in one of many Blobs. Each `Blob` contains a
//! configurable maximum of `items_per_blob`, with page-level data integrity provided by a buffer
//! pool.
//!
//! ```text
//! +--------+----- --+--- -+----------+
//! | item_0 | item_1 | ... | item_n-1 |
//! +--------+-----------+--------+----0
//!
//! n = config.items_per_blob
//! ```
//!
//! The most recent blob may not necessarily be full, in which case it will contain fewer than the
//! maximum number of items.
//!
//! Data fetched from disk is always checked for integrity before being returned. If the data is
//! found to be invalid, an error is returned instead.
//!
//! # Open Blobs
//!
//! All `Blobs` in a given `partition` are kept open during the lifetime of `Journal`. You can limit
//! the number of open blobs by using a higher number of `items_per_blob` and/or pruning old items.
//!
//! # Partition
//!
//! Blobs are stored in the legacy partition (`cfg.partition`) if it already contains data;
//! otherwise they are stored in `{cfg.partition}-blobs`.
//!
//! Metadata is stored in `{cfg.partition}-metadata`.
//!
//! # Metadata
//!
//! Metadata contains the following keys:
//! - PRUNING_BOUNDARY_KEY: Stores the pruning boundary as a u64 when it's mid-section (not a
//!   multiple of items_per_blob). Absent from legacy journals or when the boundary is
//!   section-aligned, since it can be derived from the oldest blob.
//! - RECOVERY_WATERMARK_KEY: Stores a lower bound on the last logical size at which the fixed
//!   journal's entries and metadata were synced as a coherent recovery checkpoint by an external
//!   consumer. The key is durably written during initialization for any journal last opened before
//!   this key was introduced.
//!
//! RECOVERY_WATERMARK_KEY is mainly useful when this journal is used as an index for a layered
//! journal, such as the variable journal's offsets. Standalone fixed journals do not need it to
//! recover their own size; they recover from retained blob lengths.
//!
//! # Recovery
//!
//! Sections are filled sequentially. Recovery walks the section range from oldest to newest and
//! compares each section's item count to its logical capacity:
//!
//! - A short or missing non-newest section indicates a gap in durable data; recovery stops there
//!   and truncates newer sections.
//! - The newest section may be short, since it is the normal append frontier. Recovery includes
//!   its items.
//!
//! The recovered size is the logical end of this contiguous prefix. If the persisted watermark
//! exceeds the recovered size, recovery returns a corruption error. Both the pruning boundary
//! and watermark are persisted before `init` returns.
//!
//! The recovery watermark is therefore an external recovery checkpoint, not a complete record of
//! every item that may have become durable through `commit` or storage behavior.
//!
//! # Consistency
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be durably written using `commit` or `sync`. When
//! calling `close`, all pending data is automatically synced and any open blobs are closed.
//!
//! # Pruning
//!
//! The `prune` method allows the `Journal` to prune blobs consisting entirely of items prior to a
//! given point in history.
//!
//! # Replay
//!
//! The `replay` method supports fast reading of all unpruned items into memory.

#[cfg(test)]
use super::Reader as _;
use crate::{
    journal::{
        contiguous::{metrics::FixedMetrics as Metrics, Many, Mutable},
        segmented::fixed::{Config as SegmentedConfig, Journal as SegmentedJournal},
        Error,
    },
    metadata::{Config as MetadataConfig, Metadata},
    Context,
};
use commonware_codec::CodecFixedShared;
use commonware_runtime::buffer::paged::CacheRef;
use commonware_utils::{
    sequence::VecU64,
    sync::{AsyncMutex, AsyncRwLock, AsyncRwLockReadGuard},
};
use futures::{future::try_join_all, stream::Stream, StreamExt};
use std::{
    future::Future,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::warn;

/// Items encoded for a deferred append, created by [`Journal::prepare_append`] and consumed by
/// [`Journal::append_prepared`].
pub struct PreparedAppend<A> {
    buf: Vec<u8>,
    _marker: PhantomData<A>,
}

/// Metadata key for a mid-section pruning boundary.
///
/// This key is present only when the oldest retained item is not section-aligned. It is persisted
/// after the blob state it describes exists. Recovery trusts it when it matches the oldest retained
/// section, falls back to the blob boundary when it lags (crash before metadata update), and
/// returns corruption when it is ahead of blob state or no blobs exist.
const PRUNING_BOUNDARY_KEY: u64 = 1;

/// Metadata key for an in-progress clear/reset target.
///
/// This key is synced before destructive reset work starts. If recovery sees it, recovery
/// completes the reset to the recorded target before normal bounds recovery.
pub(super) const CLEAR_TARGET_KEY: u64 = 2;

/// Metadata key for storing the recovery watermark.
const RECOVERY_WATERMARK_KEY: u64 = 3;

/// Return the first retained logical position in `section`.
#[inline]
fn first_in_section(
    pruning_boundary: u64,
    section: u64,
    items_per_blob: u64,
) -> Result<u64, Error> {
    let start = section
        .checked_mul(items_per_blob)
        .ok_or(Error::OffsetOverflow)?;
    Ok(pruning_boundary.max(start))
}

/// Maximum number of items a section's blob can physically hold. This is `items_per_blob` unless
/// the pruning boundary falls mid-section (from `init_at_size`), in which case the skipped prefix
/// reduces the capacity.
#[inline]
fn section_capacity(
    pruning_boundary: u64,
    section: u64,
    items_per_blob: u64,
) -> Result<u64, Error> {
    let start = section
        .checked_mul(items_per_blob)
        .ok_or(Error::OffsetOverflow)?;
    let skipped = pruning_boundary.saturating_sub(start).min(items_per_blob);
    Ok(items_per_blob - skipped)
}

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// Prefix for the journal partitions.
    ///
    /// Blobs are stored in `partition` (legacy) if it contains data, otherwise in
    /// `{partition}-blobs`. Metadata is stored in `{partition}-metadata`.
    pub partition: String,

    /// The maximum number of journal items to store in each blob.
    ///
    /// Retained non-tail blobs are expected to be full relative to their logical capacity. A
    /// mid-section oldest blob may physically hold fewer than this many items, and the newest blob
    /// may contain fewer items.
    pub items_per_blob: NonZeroU64,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Inner state protected by a single RwLock.
struct Inner<E: Context, A: CodecFixedShared> {
    /// The underlying segmented journal.
    journal: SegmentedJournal<E, A>,

    /// Total number of items appended (not affected by pruning).
    size: u64,

    /// Stores the recovery watermark and, when the pruning boundary is mid-section, the exact
    /// pruning boundary. Also stores an in-progress `CLEAR_TARGET_KEY` while a clear/reset is
    /// running.
    ///
    /// Metadata that advances the pruning boundary or recovery watermark is persisted only after
    /// the blob state it describes is durable. A lower recovery watermark is always safe to persist
    /// because it only expands the suffix external consumers may replay. Recovery rejects pruning
    /// metadata ahead of blob state and watermarks beyond the recovered size as corruption.
    metadata: Metadata<E, u64, VecU64>,

    /// The position before which all items have been pruned.
    pruning_boundary: u64,

    /// The earliest section modified since the last successful `commit()` or `sync()`.
    dirty_from_section: Option<u64>,
}

/// A deferred blob truncation to apply after metadata is persisted during init.
struct RecoveryRepair {
    section: u64,
    byte_offset: u64,
}

impl<E: Context, A: CodecFixedShared> Inner<E, A> {
    /// Read the item at position `pos` in the journal.
    ///
    /// # Errors
    ///
    ///  - [Error::ItemPruned] if the item at position `pos` is pruned.
    ///  - [Error::ItemOutOfRange] if the item at position `pos` does not exist.
    async fn read(&self, pos: u64, items_per_blob: u64) -> Result<A, Error> {
        if pos >= self.size {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.pruning_boundary {
            return Err(Error::ItemPruned(pos));
        }

        let section = pos / items_per_blob;
        let pos_in_section =
            pos - first_in_section(self.pruning_boundary, section, items_per_blob)?;

        self.journal
            .get(section, pos_in_section)
            .await
            .map_err(|e| {
                // Since we check bounds above, any failure here is unexpected.
                match e {
                    Error::SectionOutOfRange(e)
                    | Error::AlreadyPrunedToSection(e)
                    | Error::ItemOutOfRange(e) => {
                        Error::Corruption(format!("section/item should be found, but got: {e}"))
                    }
                    other => other,
                }
            })
    }

    /// Read an item if it can be done synchronously (e.g. without I/O), returning `None` otherwise.
    fn try_read_sync(&self, pos: u64, items_per_blob: u64) -> Option<A> {
        let mut buf = vec![0u8; SegmentedJournal::<E, A>::CHUNK_SIZE];
        self.try_read_sync_into(pos, items_per_blob, &mut buf)
    }

    /// Read an item synchronously using caller-provided buffer.
    fn try_read_sync_into(&self, pos: u64, items_per_blob: u64, buf: &mut [u8]) -> Option<A> {
        if pos >= self.size || pos < self.pruning_boundary {
            return None;
        }
        let section = pos / items_per_blob;
        let pos_in_section =
            pos - first_in_section(self.pruning_boundary, section, items_per_blob).ok()?;
        self.journal.try_get_sync_into(section, pos_in_section, buf)
    }
}

/// Implementation of `Journal` storage.
///
/// This is implemented as a wrapper around [SegmentedJournal] that provides position-based access
/// where positions are automatically mapped to (section, position_in_section) pairs.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying blob will be truncated to the last valid item). Repair is performed
/// by the underlying [SegmentedJournal] during init.
pub struct Journal<E: Context, A: CodecFixedShared> {
    /// Inner state with segmented journal and size.
    inner: AsyncRwLock<Inner<E, A>>,

    /// Serializes writers with `commit()` and `sync()` so a plain rwlock is sufficient.
    op_lock: AsyncMutex<()>,

    /// The maximum number of items per blob (section).
    items_per_blob: u64,

    /// Metrics for monitoring journal state and activity.
    metrics: Metrics<E>,
}

/// A reader guard that holds a consistent snapshot of the journal's bounds.
pub struct Reader<'a, E: Context, A: CodecFixedShared> {
    guard: AsyncRwLockReadGuard<'a, Inner<E, A>>,
    items_per_blob: u64,
    metrics: &'a Metrics<E>,
}

impl<E: Context, A: CodecFixedShared> super::Reader for Reader<'_, E, A> {
    type Item = A;

    fn bounds(&self) -> std::ops::Range<u64> {
        self.guard.pruning_boundary..self.guard.size
    }

    async fn read(&self, pos: u64) -> Result<A, Error> {
        let _timer = self.metrics.read_timer();
        self.metrics.read_calls.inc();

        // Serve from the page cache synchronously when possible, avoiding the async storage path.
        if let Some(item) = self.guard.try_read_sync(pos, self.items_per_blob) {
            self.metrics.record_cache_hits(1);
            self.metrics.items_read.inc();
            return Ok(item);
        }
        self.metrics.record_cache_misses(1);

        let item = self.guard.read(pos, self.items_per_blob).await?;
        self.metrics.items_read.inc();
        Ok(item)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let _timer = self.metrics.read_many_timer();
        self.metrics.read_many_calls.inc();
        assert!(
            positions.windows(2).all(|w| w[0] < w[1]),
            "positions must be strictly increasing"
        );
        // Validate all positions.
        for &pos in positions {
            if pos >= self.guard.size {
                return Err(Error::ItemOutOfRange(pos));
            }
            if pos < self.guard.pruning_boundary {
                return Err(Error::ItemPruned(pos));
            }
        }

        let items_per_blob = self.items_per_blob;
        let pruning_boundary = self.guard.pruning_boundary;
        let chunk_size = SegmentedJournal::<E, A>::CHUNK_SIZE;

        // Read all positions grouped by section. Each group goes through the segmented journal's
        // batched read, which serves page-cache and tip-buffer hits under a single lock acquisition
        // and reads only true misses from the blob (concurrently). This avoids one lock acquisition
        // per item that a per-item synchronous probe would incur for the warm steady state.
        let mut result: Vec<A> = Vec::with_capacity(positions.len());
        let mut reusable_buf = vec![0u8; positions.len() * chunk_size];
        let mut hits = 0u64;

        let mut group_start = 0;
        while group_start < positions.len() {
            let section = positions[group_start] / items_per_blob;

            let mut group_end = group_start + 1;
            while group_end < positions.len() && positions[group_end] / items_per_blob == section {
                group_end += 1;
            }

            let group_len = group_end - group_start;
            let first_position = first_in_section(pruning_boundary, section, items_per_blob)?;
            let section_positions: Vec<u64> = positions[group_start..group_end]
                .iter()
                .map(|&pos| pos - first_position)
                .collect();

            let buf = &mut reusable_buf[..group_len * chunk_size];
            let (items, group_hits) = self
                .guard
                .journal
                .get_many(section, &section_positions, buf)
                .await
                .map_err(|e| match e {
                    Error::SectionOutOfRange(e)
                    | Error::AlreadyPrunedToSection(e)
                    | Error::ItemOutOfRange(e) => {
                        Error::Corruption(format!("section/item should be found, but got: {e}"))
                    }
                    other => other,
                })?;

            hits += group_hits as u64;
            result.extend(items);
            group_start = group_end;
        }

        self.metrics.record_cache_hits(hits);
        self.metrics
            .record_cache_misses(positions.len() as u64 - hits);
        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result)
    }

    fn try_read_sync(&self, pos: u64) -> Option<A> {
        self.guard
            .try_read_sync(pos, self.items_per_blob)
            .map_or_else(
                || {
                    self.metrics.record_cache_misses(1);
                    None
                },
                |item| {
                    self.metrics.record_cache_hits(1);
                    self.metrics.try_read_sync_hits.inc();
                    self.metrics.items_read.inc();
                    Some(item)
                },
            )
    }

    async fn replay(
        &self,
        buffer: NonZeroUsize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error> {
        let items_per_blob = self.items_per_blob;
        let pruning_boundary = self.guard.pruning_boundary;

        // Validate bounds.
        if start_pos > self.guard.size {
            return Err(Error::ItemOutOfRange(start_pos));
        }
        if start_pos < pruning_boundary {
            return Err(Error::ItemPruned(start_pos));
        }

        let start_section = start_pos / items_per_blob;
        let start_pos_in_section =
            start_pos - first_in_section(pruning_boundary, start_section, items_per_blob)?;

        // Check all middle sections (not oldest, not tail) in range are complete.
        let journal = &self.guard.journal;
        if let (Some(oldest), Some(newest)) = (journal.oldest_section(), journal.newest_section()) {
            let first_to_check = start_section.max(oldest + 1);
            for section in first_to_check..newest {
                let len = journal.section_len(section).await?;
                if len < items_per_blob {
                    return Err(Error::Corruption(format!(
                        "section {section} incomplete: expected {items_per_blob} items, got {len}"
                    )));
                }
            }
        }

        let inner_stream = journal
            .replay(start_section, start_pos_in_section, buffer)
            .await?;

        // Transform (section, pos_in_section, item) to (global_pos, item).
        let stream = inner_stream.map(move |result| {
            result.and_then(|(section, pos_in_section, item)| {
                let global_pos = first_in_section(pruning_boundary, section, items_per_blob)?
                    .checked_add(pos_in_section)
                    .ok_or(Error::OffsetOverflow)?;
                Ok((global_pos, item))
            })
        });

        Ok(stream)
    }
}

impl<E: Context, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry in bytes.
    pub const CHUNK_SIZE: usize = SegmentedJournal::<E, A>::CHUNK_SIZE;

    /// Size of each entry in bytes (as u64).
    pub const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Mark all sections from `section` onward as dirty.
    fn mark_dirty_from(inner: &mut Inner<E, A>, section: u64) {
        inner.dirty_from_section = Some(
            inner
                .dirty_from_section
                .map_or(section, |existing| existing.min(section)),
        );
    }

    /// Update pruning-boundary and recovery-watermark entries in metadata's in-memory state.
    ///
    /// Call `inner.metadata.sync()` separately to persist the updated entries.
    fn update_metadata_entries(
        inner: &mut Inner<E, A>,
        items_per_blob: u64,
        pruning_boundary: u64,
        recovery_watermark: u64,
    ) {
        let current_pruning = inner
            .metadata
            .get(&PRUNING_BOUNDARY_KEY)
            .copied()
            .map(u64::from);
        if !pruning_boundary.is_multiple_of(items_per_blob) {
            if current_pruning != Some(pruning_boundary) {
                inner
                    .metadata
                    .put(PRUNING_BOUNDARY_KEY, pruning_boundary.into());
            }
        } else if current_pruning.is_some() {
            inner.metadata.remove(&PRUNING_BOUNDARY_KEY);
        }

        let current_watermark = inner
            .metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from);
        if current_watermark != Some(recovery_watermark) {
            inner
                .metadata
                .put(RECOVERY_WATERMARK_KEY, recovery_watermark.into());
        }
    }

    /// Update and persist pruning-boundary and recovery-watermark metadata entries.
    async fn persist_metadata_entries(
        inner: &mut Inner<E, A>,
        items_per_blob: u64,
        pruning_boundary: u64,
        recovery_watermark: u64,
    ) -> Result<(), Error> {
        Self::update_metadata_entries(inner, items_per_blob, pruning_boundary, recovery_watermark);
        inner.metadata.sync().await.map_err(Into::into)
    }

    /// Stage a recovery watermark no greater than `limit`.
    ///
    /// This is used before blob state moves backward so external consumers never see a persisted
    /// recovery checkpoint beyond the rewind/clear target.
    fn lower_recovery_watermark(inner: &mut Inner<E, A>, limit: u64) -> bool {
        let Some(current) = inner
            .metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
        else {
            return false;
        };
        if current <= limit {
            return false;
        }
        inner.metadata.put(RECOVERY_WATERMARK_KEY, limit.into());
        true
    }

    /// Stage a recovery-watermark entry no greater than `limit` in raw metadata.
    ///
    /// This is used by `init_at_size` before it clears existing blobs, before an `Inner` exists.
    #[commonware_macros::stability(ALPHA)]
    pub(super) fn update_metadata_watermark_before_clear(
        metadata: &mut Metadata<E, u64, VecU64>,
        limit: u64,
    ) -> bool {
        let Some(current_watermark) = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
        else {
            return false;
        };
        if current_watermark <= limit {
            return false;
        }
        metadata.put(RECOVERY_WATERMARK_KEY, limit.into());
        true
    }

    /// Open the metadata partition for `cfg`.
    pub(super) async fn open_metadata(
        context: E,
        cfg: &Config,
    ) -> Result<Metadata<E, u64, VecU64>, Error> {
        let meta_cfg = MetadataConfig {
            partition: format!("{}-metadata", cfg.partition),
            codec_config: (),
        };
        Metadata::<_, u64, VecU64>::init(context, meta_cfg)
            .await
            .map_err(Into::into)
    }

    /// Scan a partition and return blob names, treating a missing partition as empty.
    async fn scan_partition(context: &E, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        match context.scan(partition).await {
            Ok(blobs) => Ok(blobs),
            Err(commonware_runtime::Error::PartitionMissing(_)) => Ok(Vec::new()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Select the blobs partition using legacy-first compatibility rules.
    ///
    /// If both legacy and new blobs partitions contain data, returns corruption.
    /// If neither contains data, defaults to the new blobs partition.
    // TODO(#2941): Remove legacy partition support
    async fn select_blob_partition(context: &E, cfg: &Config) -> Result<String, Error> {
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

    /// Stage `PRUNING_BOUNDARY_KEY` in metadata, putting the mid-section boundary or removing the
    /// entry when section-aligned.
    fn stage_pruning_boundary_metadata(
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

    /// Clear blobs, recreate the tail section, reset metadata to `size`, and remove the in-progress
    /// `CLEAR_TARGET_KEY`. Called both by `clear_to_size`/`init_at_size` and during init-time
    /// crash recovery when `CLEAR_TARGET_KEY` is present.
    async fn complete_clear_to_size(
        journal: &mut SegmentedJournal<E, A>,
        metadata: &mut Metadata<E, u64, VecU64>,
        items_per_blob: u64,
        size: u64,
    ) -> Result<(), Error> {
        journal.clear().await?;
        journal.ensure_section_exists(size / items_per_blob).await?;
        Self::stage_pruning_boundary_metadata(metadata, items_per_blob, size);
        metadata.put(RECOVERY_WATERMARK_KEY, size.into());
        metadata.remove(&CLEAR_TARGET_KEY);
        metadata.sync().await.map_err(Into::into)
    }

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. The `replay` method can be
    /// used to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let metadata = Self::open_metadata(context.child("meta"), &cfg).await?;
        Self::init_with_metadata(context, cfg, metadata).await
    }

    /// Finish initialization using an already-open metadata handle. Callers use this after
    /// `open_metadata` so the metadata partition is opened exactly once.
    pub(super) async fn init_with_metadata(
        context: E,
        cfg: Config,
        mut metadata: Metadata<E, u64, VecU64>,
    ) -> Result<Self, Error> {
        let items_per_blob = cfg.items_per_blob.get();

        let blob_partition = Self::select_blob_partition(&context, &cfg).await?;
        let segmented_cfg = SegmentedConfig {
            partition: blob_partition,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
        };

        let mut journal = SegmentedJournal::init(context.child("blobs"), segmented_cfg).await?;

        // Complete any interrupted clear before recovering bounds. `complete_clear_to_size` also
        // resets the recovery watermark to the clear target, so the subsequent bounds recovery
        // sees fully consistent metadata.
        if let Some(clear_target) = metadata.get(&CLEAR_TARGET_KEY).copied().map(u64::from) {
            warn!(clear_target, "crash repair: completing interrupted clear");
            Self::complete_clear_to_size(&mut journal, &mut metadata, items_per_blob, clear_target)
                .await?;
        }

        let meta_pruning_boundary = metadata.get(&PRUNING_BOUNDARY_KEY).copied().map(u64::from);
        let meta_recovery_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from);

        let (pruning_boundary, size, recovery_watermark, repair) = Self::recover_bounds(
            &mut journal,
            items_per_blob,
            meta_pruning_boundary,
            meta_recovery_watermark,
        )
        .await?;

        // Bytes beyond the persisted recovery watermark may be readable after reopen without
        // being crash-durable, so the next commit/sync must force a data sync before advancing it.
        let dirty_from_section =
            (recovery_watermark < size).then_some(recovery_watermark / items_per_blob);
        let mut inner = Inner {
            journal,
            size,
            metadata,
            pruning_boundary,
            dirty_from_section,
        };

        // Metadata must be persisted before the rewind repair: the rewind cannot reduce the
        // recoverable size below what recover_bounds computed, so the watermark persisted here will
        // remain valid even if a crash interrupts the rewind.
        Self::persist_metadata_entries(
            &mut inner,
            items_per_blob,
            pruning_boundary,
            recovery_watermark,
        )
        .await?;

        if let Some(repair) = repair {
            inner
                .journal
                .rewind(repair.section, repair.byte_offset)
                .await?;
            inner.journal.sync(repair.section).await?;
        }

        let tail_section = size / items_per_blob;
        inner.journal.ensure_section_exists(tail_section).await?;

        let metrics = Metrics::new(context);
        metrics.update(size, pruning_boundary, items_per_blob);

        Ok(Self {
            inner: AsyncRwLock::new(inner),
            op_lock: AsyncMutex::new(()),
            items_per_blob,
            metrics,
        })
    }

    /// Recover `(pruning_boundary, size, recovery_watermark, repair)` from metadata and blob state.
    ///
    /// Pruning metadata that lags blob state is repaired from the blob boundary; pruning metadata
    /// ahead of blob state or a watermark beyond the recovered size is corruption. The caller
    /// persists metadata before applying the returned repair (see comment at the call site).
    async fn recover_bounds(
        inner: &mut SegmentedJournal<E, A>,
        items_per_blob: u64,
        meta_pruning_boundary: Option<u64>,
        meta_recovery_watermark: Option<u64>,
    ) -> Result<(u64, u64, u64, Option<RecoveryRepair>), Error> {
        let pruning_boundary = Self::recover_pruning_boundary(
            meta_pruning_boundary,
            inner.oldest_section(),
            items_per_blob,
        )?;

        let (size, repair) =
            Self::recover_by_walking_lengths(inner, items_per_blob, pruning_boundary).await?;

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
                // A legacy journal with a short non-tail section violates the old rollover-sync
                // invariant (each section was fsynced before the next received writes).
                return Err(Error::Corruption(
                    "legacy journal has a short non-tail section".into(),
                ));
            }
            // Legacy journals have no watermark. Under the old rollover-sync invariant, all
            // non-tail sections are durable; only the tail may have unfsynced data.
            None => first_in_section(pruning_boundary, size / items_per_blob, items_per_blob)?,
        };

        Ok((pruning_boundary, size, recovery_watermark, repair))
    }

    /// Recover the pruning boundary from metadata if it still matches the oldest retained section.
    ///
    /// Missing or section-aligned metadata means the blob boundary is authoritative. Mid-section
    /// metadata is trusted only when it belongs to the current oldest section.
    fn recover_pruning_boundary(
        meta_pruning_boundary: Option<u64>,
        oldest_section: Option<u64>,
        items_per_blob: u64,
    ) -> Result<u64, Error> {
        let blob_boundary = match oldest_section {
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

        let meta_oldest_section = meta_pruning_boundary / items_per_blob;
        match oldest_section {
            Some(oldest_section) if meta_oldest_section == oldest_section => {
                Ok(meta_pruning_boundary)
            }
            Some(oldest_section) if meta_oldest_section < oldest_section => {
                warn!(
                    meta_oldest_section,
                    oldest_section, "crash repair: pruning metadata stale, computing from blobs"
                );
                Ok(blob_boundary)
            }
            Some(oldest_section) => {
                // Metadata ahead of blob state should never arise: prune removes blobs before
                // sync persists metadata, and clear_to_size uses CLEAR_TARGET_KEY.
                Err(Error::Corruption(format!(
                    "pruning metadata references section {meta_oldest_section} \
                     but oldest blob is section {oldest_section}"
                )))
            }
            None => {
                // Mid-section pruning metadata with no blobs should never arise:
                // complete_clear_to_size handles CLEAR_TARGET_KEY before we get here,
                // and no other operation removes all blobs without updating metadata.
                Err(Error::Corruption(format!(
                    "pruning metadata references section {meta_oldest_section} but no blobs exist"
                )))
            }
        }
    }

    async fn section_len_within_capacity(
        inner: &SegmentedJournal<E, A>,
        items_per_blob: u64,
        pruning_boundary: u64,
        section: u64,
    ) -> Result<(u64, u64), Error> {
        let len = inner.section_len(section).await?;
        let capacity = section_capacity(pruning_boundary, section, items_per_blob)?;
        if len > capacity {
            return Err(Error::Corruption(format!(
                "section {section} has too many items: expected at most {capacity}, got {len}"
            )));
        }
        Ok((len, capacity))
    }

    /// Recover logical size by walking section lengths from oldest to newest, truncating at the
    /// first short or missing non-tail section.
    async fn recover_by_walking_lengths(
        inner: &mut SegmentedJournal<E, A>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) -> Result<(u64, Option<RecoveryRepair>), Error> {
        let oldest = inner.oldest_section();
        let newest = inner.newest_section();

        let (Some(oldest), Some(newest)) = (oldest, newest) else {
            return Ok((pruning_boundary, None));
        };

        let mut size = pruning_boundary;
        for section in oldest..=newest {
            let (len, capacity) =
                Self::section_len_within_capacity(inner, items_per_blob, pruning_boundary, section)
                    .await?;

            size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
            if len < capacity {
                if section == newest {
                    return Ok((size, None));
                }
                return Ok((
                    size,
                    Some(RecoveryRepair {
                        section,
                        byte_offset: len
                            .checked_mul(Self::CHUNK_SIZE_U64)
                            .ok_or(Error::OffsetOverflow)?,
                    }),
                ));
            }
        }

        Ok((size, None))
    }

    /// Initialize a new `Journal` instance in a pruned state at a given size.
    ///
    /// This is used for state sync to create a journal that appears to have had `size` items
    /// appended and then pruned up to that point.
    ///
    /// # Arguments
    /// * `context` - The storage context
    /// * `cfg` - Configuration for the journal
    /// * `size` - The number of operations that have been "pruned"
    ///
    /// # Behavior
    /// - Clears any existing data in the partition
    /// - Creates an empty tail blob where the next append (at position `size`) will go
    /// - `bounds().is_empty()` returns `true` (fully pruned state)
    /// - The next `append()` will write to position `size`
    ///
    /// # Post-conditions
    /// - `bounds().end` returns `size`
    /// - `bounds().is_empty()` returns `true`
    /// - `bounds.start` equals `size` (no data exists)
    ///
    /// # Crash Safety
    /// In the event of a crash during this call, upon restart recovery will ensure the journal is
    /// either still in its prior state, or has bounds `size..size`.
    #[commonware_macros::stability(ALPHA)]
    pub async fn init_at_size(context: E, cfg: Config, size: u64) -> Result<Self, Error> {
        // Fail before writing intent if existing blob partitions are already inconsistent.
        Self::select_blob_partition(&context, &cfg).await?;
        Self::init_at_size_cleared(context, cfg, size, || async { Ok(()) }).await
    }

    /// Like [Self::init_at_size], but awaits `clear_dependents` after the reset intent is durably
    /// staged and before it completes.
    ///
    /// Callers that key dependent state off this journal use this to discard that state atomically
    /// with the reset. A crash at any point leaves a durable intent that the next `init` (or
    /// [Self::init_cleared]) finishes.
    #[commonware_macros::stability(ALPHA)]
    pub(super) async fn init_at_size_cleared<F, Fut>(
        context: E,
        cfg: Config,
        size: u64,
        clear_dependents: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), Error>>,
    {
        // A journal sized at `u64::MAX` can never accept an append (the successor size
        // overflows), so reject it before staging any reset intent.
        if size == u64::MAX {
            return Err(Error::SizeOverflow);
        }

        // Stage the reset intent durably. Lower the recovery watermark first so external
        // consumers never see a persisted checkpoint beyond `size`. `init_with_metadata` will
        // detect CLEAR_TARGET_KEY and complete the clear via complete_clear_to_size before
        // recovering bounds.
        let mut metadata = Self::open_metadata(context.child("meta"), &cfg).await?;
        Self::update_metadata_watermark_before_clear(&mut metadata, size);
        metadata.put(CLEAR_TARGET_KEY, size.into());
        metadata.sync().await?;
        clear_dependents().await?;
        Self::init_with_metadata(context, cfg, metadata).await
    }

    /// Like [Self::init], but awaits `clear_dependents` before completing a staged clear.
    ///
    /// If a prior (possibly crashed) [Self::init_at_size_cleared] or
    /// [Self::stage_clear_intent] staged a `CLEAR_TARGET_KEY` reset, `clear_dependents` runs before
    /// recovery so callers can discard dependent state that the staged clear must reconcile against.
    /// With no staged reset this behaves exactly like [Self::init].
    pub(super) async fn init_cleared<F, Fut>(
        context: E,
        cfg: Config,
        clear_dependents: F,
    ) -> Result<Self, Error>
    where
        F: FnOnce() -> Fut,
        Fut: Future<Output = Result<(), Error>>,
    {
        let metadata = Self::open_metadata(context.child("meta"), &cfg).await?;
        if metadata.get(&CLEAR_TARGET_KEY).is_some() {
            clear_dependents().await?;
        }
        Self::init_with_metadata(context, cfg, metadata).await
    }

    /// Convert a global position to (section, position_in_section).
    #[inline]
    const fn position_to_section(&self, position: u64) -> (u64, u64) {
        let section = position / self.items_per_blob;
        let pos_in_section = position % self.items_per_blob;
        (section, pos_in_section)
    }

    /// Flush dirty sections to storage under the read lock, allowing concurrent reads.
    ///
    /// Sections are synced concurrently. Ordering is not required for recovery: appends only add
    /// data, so committed sections are never at risk, and recovery truncates at the first short or
    /// missing section, so a crash that leaves a gap still recovers a contiguous prefix no shorter
    /// than the last completed commit.
    async fn flush_dirty_sections(&self) -> Result<(), Error> {
        let inner = self.inner.read().await;
        if let Some(start_section) = inner.dirty_from_section {
            let tail_section = inner.size / self.items_per_blob;
            let start_section = inner
                .journal
                .oldest_section()
                .map(|oldest| start_section.max(oldest))
                // With no retained blobs, any earlier dirty section was cleared or pruned.
                // Syncing the tail section is harmless when it does not exist.
                .unwrap_or(tail_section);
            try_join_all((start_section..=tail_section).map(|section| inner.journal.sync(section)))
                .await?;
        }
        Ok(())
    }

    /// Durably persists the current state of the structure.
    ///
    /// Does not advance the recovery watermark, so external consumers may need to replay entries
    /// beyond the previous `sync()`. Use `sync()` to advance the watermark and to ensure that a
    /// crash after this call doesn't require any recovery.
    pub async fn commit(&self) -> Result<(), Error> {
        let _timer = self.metrics.commit_timer();
        self.metrics.record_commit();
        let _op_guard = self.op_lock.lock().await;
        self.flush_dirty_sections().await?;

        let mut inner = self.inner.write().await;
        inner.dirty_from_section = None;
        Ok(())
    }

    /// Durably persist the current state of the structure, ensuring no recovery is required in the
    /// event of a crash following this call.
    ///
    /// Advances the recovery watermark to the current size.
    pub async fn sync(&self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        let _op_guard = self.op_lock.lock().await;
        self.flush_dirty_sections().await?;

        let mut inner = self.inner.write().await;
        inner.dirty_from_section = None;
        let pruning_boundary = inner.pruning_boundary;
        let size = inner.size;
        Self::update_metadata_entries(&mut inner, self.items_per_blob, pruning_boundary, size);
        drop(inner);

        let inner = self.inner.read().await;
        inner.metadata.sync().await?;

        Ok(())
    }

    /// Acquire a reader guard that holds a consistent view of the journal.
    pub async fn reader(&self) -> Reader<'_, E, A> {
        Reader {
            guard: self.inner.read().await,
            items_per_blob: self.items_per_blob,
            metrics: &self.metrics,
        }
    }

    /// Return the recovery watermark.
    pub(crate) async fn recovery_watermark(&self) -> u64 {
        let inner = self.inner.read().await;
        inner
            .metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
            .expect("recovery watermark must exist after init")
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub async fn size(&self) -> u64 {
        self.inner.read().await.size
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
    pub async fn append(&self, item: &A) -> Result<u64, Error> {
        let _timer = self.metrics.append_timer();
        self.metrics.append_calls.inc();
        self.append_many_inner(Many::Flat(std::slice::from_ref(item)))
            .await
    }

    /// Append items to the journal, returning the position of the last item appended.
    ///
    /// Acquires the write lock once for all items instead of per-item.
    /// Returns [Error::EmptyAppend] if items is empty.
    pub async fn append_many<'a>(&'a self, items: Many<'a, A>) -> Result<u64, Error> {
        let _timer = self.metrics.append_many_timer();
        self.metrics.append_many_calls.inc();
        self.append_many_inner(items).await
    }

    // Shared implementation for `append` and `append_many`; public wrappers record metrics.
    async fn append_many_inner<'a>(&'a self, items: Many<'a, A>) -> Result<u64, Error> {
        self.write_encoded(self.prepare_append(items)).await
    }

    /// Encode `items` into a buffer that can be appended later with [`Self::append_prepared`].
    ///
    /// This lets callers serialize borrowed items synchronously, release those borrows, and
    /// perform the append without holding unrelated locks across journal I/O.
    pub fn prepare_append(&self, items: Many<'_, A>) -> PreparedAppend<A> {
        let mut buf = Vec::with_capacity(items.len() * A::SIZE);
        match items {
            Many::Flat(items) => {
                for item in items {
                    item.write(&mut buf);
                }
            }
            Many::Nested(nested_items) => {
                for items in nested_items {
                    for item in *items {
                        item.write(&mut buf);
                    }
                }
            }
        }
        PreparedAppend {
            buf,
            _marker: PhantomData,
        }
    }

    /// Append items encoded by [`Self::prepare_append`], returning the position of the last item
    /// appended.
    ///
    /// Returns [Error::EmptyAppend] if `prepared` contains no items.
    pub async fn append_prepared(&self, prepared: PreparedAppend<A>) -> Result<u64, Error> {
        let _timer = self.metrics.append_prepared_timer();
        self.metrics.append_prepared_calls.inc();
        self.write_encoded(prepared).await
    }

    // Write pre-encoded items; shared by all append paths. Records no call metrics.
    async fn write_encoded(&self, prepared: PreparedAppend<A>) -> Result<u64, Error> {
        let items_buf = prepared.buf;
        let items_count = items_buf.len() / A::SIZE;
        if items_count == 0 {
            return Err(Error::EmptyAppend);
        }

        let _op_guard = self.op_lock.lock().await;
        let mut inner = self.inner.write().await;

        // Reject the append before writing anything if it would push the size past `u64::MAX`.
        // This keeps the in-loop `inner.size += batch_count` and `section + 1` arithmetic safe.
        inner
            .size
            .checked_add(items_count as u64)
            .ok_or(Error::SizeOverflow)?;

        let first_dirty_section = inner.size / self.items_per_blob;
        Self::mark_dirty_from(&mut inner, first_dirty_section);
        let mut written = 0;
        while written < items_count {
            let (section, pos_in_section) = self.position_to_section(inner.size);
            let remaining_space = (self.items_per_blob - pos_in_section) as usize;
            let batch_count = remaining_space.min(items_count - written);
            let start = written * A::SIZE;
            let end = start + batch_count * A::SIZE;

            inner
                .journal
                .append_raw(section, &items_buf[start..end])
                .await?;
            inner.size += batch_count as u64;
            written += batch_count;

            if inner.size.is_multiple_of(self.items_per_blob) {
                inner.journal.ensure_section_exists(section + 1).await?;
            }
        }

        self.metrics
            .update(inner.size, inner.pruning_boundary, self.items_per_blob);
        Ok(inner.size - 1)
    }

    /// Rewind the journal to the given `size`. Returns [Error::InvalidRewind] if the rewind point
    /// precedes the oldest retained element. The journal is not synced after rewinding.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until `commit()` or `sync()` is
    ///   called.
    /// * This operation is not atomic, but it will always leave the journal in a consistent state
    ///   in the event of failure since blobs are always removed from newest to oldest.
    pub async fn rewind(&self, size: u64) -> Result<(), Error> {
        let _op_guard = self.op_lock.lock().await;
        let mut inner = self.inner.write().await;

        match size.cmp(&inner.size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        if size < inner.pruning_boundary {
            return Err(Error::InvalidRewind(size));
        }

        let section = size / self.items_per_blob;
        let pos_in_section =
            size - first_in_section(inner.pruning_boundary, section, self.items_per_blob)?;
        let byte_offset = pos_in_section
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        let should_sync_metadata = Self::lower_recovery_watermark(&mut inner, size);
        drop(inner);

        if should_sync_metadata {
            let inner = self.inner.read().await;
            inner.metadata.sync().await?;
        }

        let mut inner = self.inner.write().await;
        inner.journal.rewind(section, byte_offset).await?;
        inner.size = size;
        Self::mark_dirty_from(&mut inner, section);
        self.metrics
            .update(inner.size, inner.pruning_boundary, self.items_per_blob);

        Ok(())
    }

    /// Return the location before which all items have been pruned.
    pub async fn pruning_boundary(&self) -> u64 {
        let inner = self.inner.read().await;
        inner.pruning_boundary
    }

    /// Allow the journal to prune items older than `min_item_pos`. The journal may not prune all
    /// such items in order to preserve blob boundaries, but the amount of such items will always be
    /// less than the configured number of items per blob. Returns true if any items were pruned.
    ///
    /// Note that this operation may NOT be atomic, however it's guaranteed not to leave gaps in the
    /// event of failure as items are always pruned in order from oldest to newest.
    pub async fn prune(&self, min_item_pos: u64) -> Result<bool, Error> {
        let _op_guard = self.op_lock.lock().await;
        let mut inner = self.inner.write().await;

        // Calculate the section that would contain min_item_pos
        let target_section = min_item_pos / self.items_per_blob;

        // Calculate the tail section.
        let tail_section = inner.size / self.items_per_blob;

        // Cap to tail section. The tail section is guaranteed to exist by our invariant.
        let min_section = std::cmp::min(target_section, tail_section);

        let pruned = inner.journal.prune(min_section).await?;

        // After pruning, update pruning_boundary to the start of the oldest remaining section
        if pruned {
            let new_oldest = inner
                .journal
                .oldest_section()
                .expect("all sections pruned - violates tail section invariant");
            // Pruning boundary only moves forward
            assert!(inner.pruning_boundary < new_oldest * self.items_per_blob);
            inner.pruning_boundary = new_oldest * self.items_per_blob;
            if let Some(dirty_from) = inner.dirty_from_section {
                inner.dirty_from_section = Some(dirty_from.max(new_oldest));
            }
            self.metrics
                .update(inner.size, inner.pruning_boundary, self.items_per_blob);
        }

        Ok(pruned)
    }

    /// Remove any persisted data created by the journal.
    ///
    /// # Crash Safety
    ///
    /// This operation is intended for final teardown and is not crash-safe. If interrupted,
    /// reopening the same partition may observe partially removed state. Use [Self::init_at_size]
    /// for a recoverable reset.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy inner journal
        let inner = self.inner.into_inner();
        inner.journal.destroy().await?;

        // Destroy metadata
        inner.metadata.destroy().await?;

        Ok(())
    }

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused. After clearing, the
    /// journal will behave as if initialized with `init_at_size(new_size)`.
    ///
    /// # Crash Safety
    ///
    /// In the event of a crash during this call, upon restart recovery will ensure the journal is
    /// either still in its prior state, or has bounds `new_size..new_size`.
    pub(crate) async fn clear_to_size(&self, new_size: u64) -> Result<(), Error> {
        let _op_guard = self.op_lock.lock().await;
        let mut inner = self.inner.write().await;

        // Lower the watermark in-memory and stage the clear intent in the same metadata sync, so
        // external consumers never see a persisted recovery checkpoint beyond `new_size`.
        Self::lower_recovery_watermark(&mut inner, new_size);
        inner.metadata.put(CLEAR_TARGET_KEY, new_size.into());
        inner.metadata.sync().await?;

        let Inner {
            journal, metadata, ..
        } = &mut *inner;
        Self::complete_clear_to_size(journal, metadata, self.items_per_blob, new_size).await?;

        inner.size = new_size;
        inner.pruning_boundary = new_size;
        inner.dirty_from_section = None;

        self.metrics
            .update(inner.size, inner.pruning_boundary, self.items_per_blob);
        Ok(())
    }

    /// Durably stage a clear to `new_size` without completing it.
    ///
    /// This lowers the recovery watermark and persists `CLEAR_TARGET_KEY`, leaving a recoverable
    /// intent so a caller can clear dependent sibling state before calling `clear_to_size` to
    /// finish. If a crash interrupts the sequence, the next `init` completes the staged clear.
    /// The follow-up `clear_to_size` re-stages the same target idempotently.
    #[commonware_macros::stability(ALPHA)]
    pub(super) async fn stage_clear_intent(&self, new_size: u64) -> Result<(), Error> {
        let _op_guard = self.op_lock.lock().await;
        let mut inner = self.inner.write().await;

        Self::lower_recovery_watermark(&mut inner, new_size);
        inner.metadata.put(CLEAR_TARGET_KEY, new_size.into());
        inner.metadata.sync().await.map_err(Into::into)
    }

    /// Test helper: Read the item at the given position.
    #[cfg(test)]
    pub(crate) async fn read(&self, pos: u64) -> Result<A, Error> {
        self.reader().await.read(pos).await
    }

    /// Test helper: Return the bounds of the journal.
    #[cfg(test)]
    pub(crate) async fn bounds(&self) -> std::ops::Range<u64> {
        self.reader().await.bounds()
    }

    /// Test helper: Get the oldest section from the internal segmented journal.
    #[cfg(test)]
    pub(crate) async fn test_oldest_section(&self) -> Option<u64> {
        let inner = self.inner.read().await;
        inner.journal.oldest_section()
    }

    /// Test helper: Get the newest section from the internal segmented journal.
    #[cfg(test)]
    pub(crate) async fn test_newest_section(&self) -> Option<u64> {
        let inner = self.inner.read().await;
        inner.journal.newest_section()
    }

    /// Test helper: Set and persist the recovery watermark directly.
    #[cfg(test)]
    pub(crate) async fn test_set_recovery_watermark(&self, watermark: u64) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        inner.metadata.put(RECOVERY_WATERMARK_KEY, watermark.into());
        inner.metadata.sync().await.map_err(Into::into)
    }
}

// Implement Contiguous trait for fixed-length journals
impl<E: Context, A: CodecFixedShared> super::Contiguous for Journal<E, A> {
    type Item = A;

    async fn reader(&self) -> impl super::Reader<Item = A> + '_ {
        Self::reader(self).await
    }

    async fn size(&self) -> u64 {
        Self::size(self).await
    }
}

impl<E: Context, A: CodecFixedShared> Mutable for Journal<E, A> {
    async fn append(&mut self, item: &Self::Item) -> Result<u64, Error> {
        Self::append(self, item).await
    }

    async fn append_many<'a>(&'a mut self, items: Many<'a, Self::Item>) -> Result<u64, Error> {
        Self::append_many(self, items).await
    }

    async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        Self::prune(self, min_position).await
    }

    async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        Self::rewind(self, size).await
    }

    async fn commit(&self) -> Result<(), Error> {
        Self::commit(self).await
    }

    async fn sync(&self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Self::destroy(self).await
    }
}

#[commonware_macros::stability(ALPHA)]
impl<E: Context, A: CodecFixedShared> crate::journal::authenticated::Inner<E> for Journal<E, A> {
    type Config = Config;

    async fn init<
        F: crate::merkle::Family,
        H: commonware_cryptography::Hasher,
        S: commonware_parallel::Strategy,
    >(
        context: E,
        merkle_cfg: crate::merkle::full::Config<S>,
        journal_cfg: Self::Config,
        rewind_predicate: fn(&A) -> bool,
        bagging: crate::merkle::Bagging,
    ) -> Result<
        crate::journal::authenticated::Journal<F, E, Self, H, S>,
        crate::journal::authenticated::Error<F>,
    > {
        crate::journal::authenticated::Journal::<F, E, Self, H, S>::new(
            context,
            merkle_cfg,
            journal_cfg,
            rewind_predicate,
            bagging,
        )
        .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::FixedSize;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic::{self, Context},
        Blob, BufferPooler, Error as RuntimeError, Metrics as _, Runner, Storage, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use futures::{pin_mut, StreamExt};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);

    /// Generate a SHA-256 digest for the given value.
    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    fn test_cfg(pooler: &impl BufferPooler, items_per_blob: NonZeroU64) -> Config {
        Config {
            partition: "test-partition".into(),
            items_per_blob,
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    fn blob_partition(cfg: &Config) -> String {
        format!("{}-blobs", cfg.partition)
    }

    #[test_traced]
    fn test_fixed_init_marks_suffix_past_recovery_watermark_dirty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(10));
            cfg.partition = "init-adopted-fixed".into();

            let journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            journal.append(&1).await.unwrap();
            journal.append(&2).await.unwrap();
            journal.sync().await.unwrap();
            // Simulate the state left by a crash after item 2 became visible to recovery, but
            // before the persisted recovery watermark advanced past item 1.
            journal.test_set_recovery_watermark(1).await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size().await, 2);

            // Regression: init used to recover size 2 while marking no data sections dirty.
            // commit() would then skip section syncs and succeed even though the recovered suffix
            // had not been durably adopted. With the fix, item 2's section is dirty, so the forced
            // sync failure below must surface.
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                sync_rate: Some(1.0),
                ..Default::default()
            };
            assert!(
                journal.commit().await.is_err(),
                "commit() must sync recovered data beyond the persisted recovery watermark"
            );
        });
    }

    async fn scan_partition(context: &Context, partition: &str) -> Vec<Vec<u8>> {
        match context.scan(partition).await {
            Ok(blobs) => blobs,
            Err(RuntimeError::PartitionMissing(_)) => Vec::new(),
            Err(err) => panic!("Failed to scan partition {partition}: {err}"),
        }
    }

    #[test_traced]
    fn test_fixed_journal_init_conflicting_partitions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let legacy_partition = cfg.partition.clone();
            let blobs_partition = blob_partition(&cfg);

            let (legacy_blob, _) = context
                .open(&legacy_partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open legacy blob");
            legacy_blob
                .write_at_sync(0, vec![0u8; 1])
                .await
                .expect("Failed to write legacy blob");

            let (new_blob, _) = context
                .open(&blobs_partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open new blob");
            new_blob
                .write_at_sync(0, vec![0u8; 1])
                .await
                .expect("Failed to write new blob");

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_prefers_legacy_partition() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let legacy_partition = cfg.partition.clone();
            let blobs_partition = blob_partition(&cfg);

            // Seed legacy partition so it is selected.
            let (legacy_blob, _) = context
                .open(&legacy_partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open legacy blob");
            legacy_blob
                .write_at_sync(0, vec![0u8; 1])
                .await
                .expect("Failed to write legacy blob");

            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            journal.append(&test_digest(1)).await.unwrap();
            journal.sync().await.unwrap();
            drop(journal);

            let legacy_blobs = scan_partition(&context, &legacy_partition).await;
            let new_blobs = scan_partition(&context, &blobs_partition).await;
            assert!(!legacy_blobs.is_empty());
            assert!(new_blobs.is_empty());
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_defaults_to_blobs_partition() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let legacy_partition = cfg.partition.clone();
            let blobs_partition = blob_partition(&cfg);

            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            journal.append(&test_digest(1)).await.unwrap();
            journal.sync().await.unwrap();
            drop(journal);

            let legacy_blobs = scan_partition(&context, &legacy_partition).await;
            let new_blobs = scan_partition(&context, &blobs_partition).await;
            assert!(legacy_blobs.is_empty());
            assert!(!new_blobs.is_empty());
        });
    }

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(&context, NZU64!(2));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append an item to the journal
            let mut pos = journal
                .append(&test_digest(0))
                .await
                .expect("failed to append data 0");
            assert_eq!(pos, 0);

            // Drop the journal and re-initialize it to simulate a restart
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            let cfg = test_cfg(&context, NZU64!(2));
            let journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size().await, 1);

            // Append two more items to the journal to trigger a new blob creation
            pos = journal
                .append(&test_digest(1))
                .await
                .expect("failed to append data 1");
            assert_eq!(pos, 1);
            pos = journal
                .append(&test_digest(2))
                .await
                .expect("failed to append data 2");
            assert_eq!(pos, 2);

            // Read the items back
            let item0 = journal.read(0).await.expect("failed to read data 0");
            assert_eq!(item0, test_digest(0));
            let item1 = journal.read(1).await.expect("failed to read data 1");
            assert_eq!(item1, test_digest(1));
            let item2 = journal.read(2).await.expect("failed to read data 2");
            assert_eq!(item2, test_digest(2));
            let err = journal.read(3).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::ItemOutOfRange(3)));

            // Sync the journal
            journal.sync().await.expect("failed to sync journal");

            // Pruning to 1 should be a no-op because there's no blob with only older items.
            journal.prune(1).await.expect("failed to prune journal 1");

            // Pruning to 2 should allow the first blob to be pruned.
            journal.prune(2).await.expect("failed to prune journal 2");
            assert_eq!(journal.bounds().await.start, 2);

            // Reading from the first blob should fail since it's now pruned
            let result0 = journal.read(0).await;
            assert!(matches!(result0, Err(Error::ItemPruned(0))));
            let result1 = journal.read(1).await;
            assert!(matches!(result1, Err(Error::ItemPruned(1))));

            // Third item should still be readable
            let result2 = journal.read(2).await.unwrap();
            assert_eq!(result2, test_digest(2));

            // Should be able to continue to append items
            for i in 3..10 {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Check no-op pruning
            journal.prune(0).await.expect("no-op pruning failed");
            assert_eq!(journal.inner.read().await.journal.oldest_section(), Some(1));
            assert_eq!(journal.inner.read().await.journal.newest_section(), Some(5));
            assert_eq!(journal.bounds().await.start, 2);

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob.get())
                .await
                .expect("failed to prune journal 2");
            assert_eq!(journal.inner.read().await.journal.oldest_section(), Some(3));
            assert_eq!(journal.inner.read().await.journal.newest_section(), Some(5));
            assert_eq!(journal.bounds().await.start, 6);

            // Try pruning (more than) everything in the journal.
            journal
                .prune(10000)
                .await
                .expect("failed to max-prune journal");
            let size = journal.size().await;
            assert_eq!(size, 10);
            assert_eq!(journal.test_oldest_section().await, Some(5));
            assert_eq!(journal.test_newest_section().await, Some(5));
            // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
            // will be empty, and there will be no retained items.
            let bounds = journal.bounds().await;
            assert!(bounds.is_empty());
            // bounds.start should equal bounds.end when empty.
            assert_eq!(bounds.start, size);

            // Replaying from 0 should fail since all items before bounds.start are pruned
            {
                let reader = journal.reader().await;
                let result = reader.replay(NZUsize!(1024), 0).await;
                assert!(matches!(result, Err(Error::ItemPruned(0))));
            }

            // Replaying from pruning_boundary should return empty stream
            {
                let reader = journal.reader().await;
                let res = reader.replay(NZUsize!(1024), 0).await;
                assert!(matches!(res, Err(Error::ItemPruned(_))));

                let reader = journal.reader().await;
                let stream = reader
                    .replay(NZUsize!(1024), journal.bounds().await.start)
                    .await
                    .expect("failed to replay journal from pruning boundary");
                pin_mut!(stream);
                let mut items = Vec::new();
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }
                assert_eq!(items, Vec::<u64>::new());
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Append a lot of data to make sure we exercise page cache paging boundaries.
    #[test_traced]
    fn test_fixed_journal_append_a_lot_of_data() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(10000);
        executor.start(|context| async move {
            let cfg = test_cfg(&context, ITEMS_PER_BLOB);
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            // Append 2 blobs worth of items.
            for i in 0u64..ITEMS_PER_BLOB.get() * 2 - 1 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            // Sync, reopen, then read back.
            journal.sync().await.expect("failed to sync journal");
            drop(journal);
            let journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            for i in 0u64..10000 {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i));
            }
            journal.destroy().await.expect("failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay() {
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(&context, ITEMS_PER_BLOB);
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Read them back the usual way.
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let item: Digest = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i), "i={i}");
            }

            // Replay should return all items
            {
                let reader = journal.reader().await;
                let stream = reader
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item, "pos={pos}, item={item:?}");
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }

                // Make sure all items were replayed
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
                );
                items.sort();
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos);
                }
            }

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Corrupt one of the bytes and make sure it's detected.
            let (blob, _) = context
                .open(&blob_partition(&cfg), &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Write junk bytes.
            let bad_bytes = 123456789u32;
            blob.write_at_sync(1, bad_bytes.to_be_bytes().to_vec())
                .await
                .expect("Failed to write bad bytes");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Make sure reading an item that resides in the corrupted page fails.
            let err = journal
                .read(40 * ITEMS_PER_BLOB.get() + 1)
                .await
                .unwrap_err();
            assert!(matches!(err, Error::Runtime(_)));

            // Replay all items.
            {
                let mut error_found = false;
                let reader = journal.reader().await;
                let stream = reader
                    .replay(NZUsize!(1024), 0)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert_eq!(test_digest(pos), item);
                            items.push(pos);
                        }
                        Err(err) => {
                            error_found = true;
                            assert!(matches!(err, Error::Runtime(_)));
                            break;
                        }
                    }
                }
                assert!(error_found); // error should abort replay
            }
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_with_missing_historical_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..5 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Delete a middle blob (external corruption). The watermark (5) now exceeds the
            // recoverable contiguous prefix, which is corruption.
            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_partial_replay() {
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        // 53 % 7 = 4, which will trigger a non-trivial seek in the starting blob to reach the
        // starting position.
        const START_POS: u64 = 53;

        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(&context, ITEMS_PER_BLOB);
            let journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append many items, filling 100 blobs and part of the 101st
            for i in 0u64..(ITEMS_PER_BLOB.get() * 100 + ITEMS_PER_BLOB.get() / 2) {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }

            // Replay should return all items except the first `START_POS`.
            {
                let reader = journal.reader().await;
                let stream = reader
                    .replay(NZUsize!(1024), START_POS)
                    .await
                    .expect("failed to replay journal");
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    match result {
                        Ok((pos, item)) => {
                            assert!(pos >= START_POS, "pos={pos}, expected >= {START_POS}");
                            assert_eq!(
                                test_digest(pos),
                                item,
                                "Item at position {pos} did not match expected digest"
                            );
                            items.push(pos);
                        }
                        Err(err) => panic!("Failed to read item: {err}"),
                    }
                }

                // Make sure all items were replayed
                assert_eq!(
                    items.len(),
                    ITEMS_PER_BLOB.get() as usize * 100 + ITEMS_PER_BLOB.get() as usize / 2
                        - START_POS as usize
                );
                items.sort();
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos - START_POS);
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rejects_corrupted_tail_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(3));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..5 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Truncate the tail blob by 1 byte (external corruption). The watermark (5) now
            // exceeds the recoverable size, which is corruption.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .unwrap();
            blob.resize(size - 1).await.unwrap();
            blob.sync().await.unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Simulate a crash after recovery persists metadata but before the rewind repair completes.
    /// The stale sections beyond the repair point still exist. The next init must succeed: it
    /// re-derives the same size from blob lengths, and the persisted watermark is still within
    /// the recovered size.
    #[test_traced]
    fn test_fixed_journal_crash_during_recovery_repair() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Fill 3 sections (0..15), sync everything.
            for i in 0..15u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            assert_eq!(journal.recovery_watermark().await, 15);

            // Shorten section 1 to simulate a short non-tail section. Recovery will compute
            // size=9 (section 0 full + 4 items in section 1) and generate a repair.
            {
                let mut inner = journal.inner.write().await;
                inner
                    .journal
                    .rewind_section(1, 4 * Digest::SIZE as u64)
                    .await
                    .unwrap();
                inner.journal.sync(1).await.unwrap();
            }

            // Persist the recovered metadata (watermark=9) as init_with_metadata does before
            // applying the rewind repair. This simulates a crash after metadata sync but before
            // the repair removes stale sections.
            {
                let mut inner = journal.inner.write().await;
                Journal::<_, Digest>::update_metadata_entries(
                    &mut inner,
                    cfg.items_per_blob.get(),
                    0,
                    9,
                );
                inner.metadata.sync().await.unwrap();
            }
            drop(journal);

            // Sections 2 (and the empty tail at 3) still exist. Init must succeed and the
            // rewind must remove the stale sections.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("init should succeed after crash during recovery repair");
            assert_eq!(journal.bounds().await, 0..9);
            assert_eq!(journal.recovery_watermark().await, 9);
            assert_eq!(journal.read(8).await.unwrap(), test_digest(8));
            assert!(matches!(
                journal.read(9).await,
                Err(Error::ItemOutOfRange(9))
            ));
            assert_eq!(
                journal.test_newest_section().await,
                Some(1),
                "stale sections beyond the repair point should be removed"
            );

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_accepts_clean_short_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let segmented_cfg = SegmentedConfig {
                partition: blob_partition(&cfg),
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            };
            let mut inner =
                SegmentedJournal::<_, Digest>::init(context.child("blobs"), segmented_cfg)
                    .await
                    .unwrap();

            for i in 0..5 {
                inner.append(0, &test_digest(i)).await.unwrap();
            }
            for i in 5..7 {
                inner.append(1, &test_digest(i)).await.unwrap();
            }
            inner.sync(0).await.unwrap();
            inner.sync(1).await.unwrap();

            let (size, repair) = Journal::<_, Digest>::recover_by_walking_lengths(&mut inner, 5, 0)
                .await
                .unwrap();
            assert_eq!(size, 7);
            assert!(repair.is_none());
            inner.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_accepts_clean_empty_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let segmented_cfg = SegmentedConfig {
                partition: blob_partition(&cfg),
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            };
            let mut inner =
                SegmentedJournal::<_, Digest>::init(context.child("blobs"), segmented_cfg)
                    .await
                    .unwrap();

            for i in 0..5 {
                inner.append(0, &test_digest(i)).await.unwrap();
            }
            inner.ensure_section_exists(1).await.unwrap();
            inner.sync(0).await.unwrap();
            inner.sync(1).await.unwrap();

            let (size, repair) = Journal::<_, Digest>::recover_by_walking_lengths(&mut inner, 5, 0)
                .await
                .unwrap();
            assert_eq!(size, 5);
            assert!(repair.is_none());
            inner.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_fallback_truncates_after_short_oldest_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .expect("failed to initialize journal at size");

            for i in 0..8u64 {
                journal
                    .append(&test_digest(100 + i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            assert_eq!(journal.bounds().await, 7..15);

            {
                let mut inner = journal.inner.write().await;
                inner.metadata.put(RECOVERY_WATERMARK_KEY, 6u64.into());
                inner
                    .metadata
                    .sync()
                    .await
                    .expect("failed to sync lower recovery watermark");
            }
            drop(journal);

            let (blob, size) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .expect("failed to open oldest blob");
            blob.resize(size - 1).await.expect("failed to corrupt blob");
            blob.sync().await.expect("failed to sync blob");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 7..9);
            assert_eq!(journal.read(7).await.unwrap(), test_digest(100));
            assert_eq!(journal.read(8).await.unwrap(), test_digest(101));
            assert!(matches!(
                journal.read(9).await,
                Err(Error::ItemOutOfRange(9))
            ));
            assert_eq!(journal.test_oldest_section().await, Some(1));
            assert_eq!(journal.inner.read().await.journal.newest_section(), Some(1));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_stale_pruning_metadata_preserves_watermark() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .expect("failed to initialize journal at size");

            for i in 0..10u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            assert_eq!(journal.bounds().await, 7..17);

            {
                let mut inner = journal.inner.write().await;
                inner
                    .journal
                    .rewind_section(2, 2 * Digest::SIZE as u64)
                    .await
                    .expect("failed to shorten anchored section");
                inner
                    .journal
                    .sync(2)
                    .await
                    .expect("failed to sync shortened anchored section");
                inner.metadata.put(RECOVERY_WATERMARK_KEY, 12u64.into());
                inner
                    .metadata
                    .sync()
                    .await
                    .expect("failed to sync recovery watermark");
            }
            drop(journal);

            // Remove the metadata's oldest section so PRUNING_BOUNDARY_KEY=7 is stale. The
            // watermark is preserved because length-based recovery ends at the same point.
            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .expect("failed to remove stale oldest section");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 10..12);
            assert_eq!(journal.recovery_watermark().await, 12);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
            assert_eq!(journal.read(11).await.unwrap(), test_digest(4));
            assert!(matches!(
                journal.read(12).await,
                Err(Error::ItemOutOfRange(12))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_stale_pruning_metadata_without_watermark_walks_lengths() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .expect("failed to initialize journal at size");

            for i in 0..10u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            assert_eq!(journal.bounds().await, 7..17);

            {
                let mut inner = journal.inner.write().await;
                inner.metadata.remove(&RECOVERY_WATERMARK_KEY);
                inner
                    .metadata
                    .sync()
                    .await
                    .expect("failed to remove recovery watermark");
            }
            drop(journal);

            // Remove the metadata's oldest section so PRUNING_BOUNDARY_KEY=7 is stale. Without a
            // recovery watermark, recovery must still walk lengths from the recovered blob boundary.
            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .expect("failed to remove stale oldest section");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 10..17);
            // No watermark: watermark at the tail section start, not size.
            assert_eq!(journal.recovery_watermark().await, 15);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
            assert_eq!(journal.read(16).await.unwrap(), test_digest(9));

            // After sync, watermark advances to the full recovered size.
            journal.sync().await.expect("failed to sync");
            assert_eq!(journal.recovery_watermark().await, 17);

            journal.destroy().await.unwrap();
        });
    }

    /// Pruning metadata ahead of the oldest blob is not a reachable crash state: prune removes
    /// blobs before sync persists metadata, and clear_to_size uses CLEAR_TARGET_KEY for atomicity.
    /// Verify it is rejected as corruption.
    #[test_traced]
    fn test_fixed_journal_pruning_metadata_ahead_of_blobs_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 3)
                    .await
                    .unwrap();

            // Append 12 items (positions 3..15) spanning sections 0, 1, 2.
            for i in 0..12u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            assert_eq!(journal.bounds().await, 3..15);

            // Set PRUNING_BOUNDARY_KEY to 8 (section 1) and lower the watermark so it won't
            // independently trigger the watermark > size corruption check. Then remove section 1's
            // blob so section 0 is the oldest. The pruning metadata now references a section ahead
            // of the oldest blob, which is the corruption we're testing.
            {
                let mut inner = journal.inner.write().await;
                inner.metadata.put(PRUNING_BOUNDARY_KEY, 8u64.into());
                inner.metadata.put(RECOVERY_WATERMARK_KEY, 3u64.into());
                inner.metadata.sync().await.unwrap();
            }
            drop(journal);

            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Mid-section pruning metadata with no blobs is not a reachable crash state (see comment in
    /// `recover_bounds`). Verify it is rejected as corruption rather than silently recovering empty.
    #[test_traced]
    fn test_fixed_journal_pruning_metadata_with_no_blobs_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Remove all blobs but leave metadata (with PRUNING_BOUNDARY_KEY=7) intact.
            for name in scan_partition(&context, &blob_partition(&cfg)).await {
                context
                    .remove(&blob_partition(&cfg), Some(&name))
                    .await
                    .unwrap();
            }

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_legacy_recovery_installs_watermark() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..12u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");

            {
                let mut inner = journal.inner.write().await;
                inner.metadata.remove(&RECOVERY_WATERMARK_KEY);
                inner
                    .metadata
                    .sync()
                    .await
                    .expect("failed to remove recovery watermark");
            }
            drop(journal);

            // Legacy recovery sets watermark to the tail section start, not size, so the tail
            // is marked dirty and fsynced before the watermark advances.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover legacy journal");
            assert_eq!(journal.bounds().await, 0..12);
            assert_eq!(journal.recovery_watermark().await, 10);

            // After sync, the watermark advances to the full size.
            journal
                .sync()
                .await
                .expect("failed to sync after legacy recovery");
            assert_eq!(journal.recovery_watermark().await, 12);

            journal.destroy().await.unwrap();
        });
    }

    /// Regression: legacy upgrade (no RECOVERY_WATERMARK_KEY) must mark all recovered sections
    /// dirty so they are fsynced before the watermark advances. Without this, init could install
    /// a durable watermark for data that was only in the OS page cache.
    #[test_traced]
    fn test_fixed_journal_legacy_upgrade_marks_recovered_sections_dirty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..7u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Remove the watermark to simulate a legacy journal.
            {
                let mut inner = journal.inner.write().await;
                inner.metadata.remove(&RECOVERY_WATERMARK_KEY);
                inner.metadata.sync().await.unwrap();
            }
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size().await, 7);
            // Watermark at tail section start (section 1 = position 5).
            assert_eq!(journal.recovery_watermark().await, 5);

            // Inject sync faults. If recovered sections were not marked dirty, commit would
            // skip the data sync and succeed despite the fault.
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                sync_rate: Some(1.0),
                ..Default::default()
            };
            assert!(
                journal.commit().await.is_err(),
                "commit must sync recovered data before the watermark can advance"
            );
        });
    }

    #[test_traced]
    fn test_fixed_journal_update_metadata_watermark_before_clear_lowers_only() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let mut metadata =
                Metadata::<_, u64, VecU64>::init(context.child("metadata"), meta_cfg)
                    .await
                    .expect("failed to initialize metadata");
            metadata.put(RECOVERY_WATERMARK_KEY, 7u64.into());

            let changed =
                Journal::<_, Digest>::update_metadata_watermark_before_clear(&mut metadata, 9);
            assert!(!changed);
            let persisted_watermark = metadata
                .get(&RECOVERY_WATERMARK_KEY)
                .copied()
                .map(u64::from)
                .expect("missing recovery watermark");
            assert_eq!(persisted_watermark, 7);

            let changed =
                Journal::<_, Digest>::update_metadata_watermark_before_clear(&mut metadata, 5);
            assert!(changed);
            let persisted_watermark = metadata
                .get(&RECOVERY_WATERMARK_KEY)
                .copied()
                .map(u64::from)
                .expect("missing recovery watermark");
            assert_eq!(persisted_watermark, 5);
        });
    }

    #[test_traced]
    fn test_fixed_journal_prune_to_blob_boundary_removes_pruning_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .expect("failed to initialize journal at size");

            for i in 0..8u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            assert_eq!(journal.bounds().await, 7..15);

            journal.prune(10).await.expect("failed to prune journal");
            journal.sync().await.expect("failed to sync pruned journal");
            assert_eq!(journal.bounds().await, 10..15);
            drop(journal);

            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let metadata = Metadata::<_, u64, VecU64>::init(context.child("metadata"), meta_cfg)
                .await
                .expect("failed to reopen metadata");
            assert!(metadata.get(&PRUNING_BOUNDARY_KEY).is_none());
            drop(metadata);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to reopen journal");
            assert_eq!(journal.bounds().await, 10..15);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_rejects_overlong_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..5u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");

            {
                let extra = test_digest(99);
                let mut inner = journal.inner.write().await;
                inner
                    .journal
                    .append_raw(0, extra.as_ref())
                    .await
                    .expect("failed to append extra item");
                inner
                    .journal
                    .sync(0)
                    .await
                    .expect("failed to sync corrupted section");
            }
            drop(journal);

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced("DEBUG")]
    fn test_fixed_journal_recover_from_unwritten_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 10 items per blob.
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Add only a single item
            journal
                .append(&test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size().await, 1);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually extend the blob to simulate a failure where the file was extended, but no
            // bytes were written due to failure.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at_sync(size, vec![0u8; PAGE_SIZE.get() as usize * 3])
                .await
                .expect("Failed to extend blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // The zero-filled pages are detected as invalid (bad checksum) and truncated.
            // No items should be lost since we called sync before the corruption.
            assert_eq!(journal.size().await, 1);

            // Make sure journal still works for appending.
            journal
                .append(&test_digest(1))
                .await
                .expect("failed to append data");

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewinding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(&context, NZU64!(2));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert!(matches!(
                journal.rewind(1).await,
                Err(Error::InvalidRewind(1))
            ));

            // Append an item to the journal
            journal
                .append(&test_digest(0))
                .await
                .expect("failed to append data 0");
            assert_eq!(journal.size().await, 1);
            assert!(matches!(journal.rewind(1).await, Ok(()))); // should be no-op
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size().await, 0);

            // append 7 items
            for i in 0..7 {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }
            assert_eq!(journal.size().await, 7);

            // rewind back to item #4, which should prune 2 blobs
            assert!(matches!(journal.rewind(4).await, Ok(())));
            assert_eq!(journal.size().await, 4);

            // rewind back to empty and ensure all blobs are rewound over
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size().await, 0);

            // stress test: add 100 items, rewind 49, repeat x10.
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(&test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size().await - 49).await.unwrap();
            }
            const ITEMS_REMAINING: u64 = 10 * (100 - 49);
            assert_eq!(journal.size().await, ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Repeat with a different blob size (3 items per blob)
            let mut cfg = test_cfg(&context, NZU64!(3));
            cfg.partition = "test-partition-2".into();
            let journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(&test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size().await - 49).await.unwrap();
            }
            assert_eq!(journal.size().await, ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Make sure re-opened journal is as expected
            let journal: Journal<_, Digest> = Journal::init(context.child("third"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size().await, 10 * (100 - 49));

            // Make sure rewinding works after pruning
            journal.prune(300).await.expect("pruning failed");
            assert_eq!(journal.size().await, ITEMS_REMAINING);
            // Rewinding prior to our prune point should fail.
            assert!(matches!(
                journal.rewind(299).await,
                Err(Error::InvalidRewind(299))
            ));
            // Rewinding to the prune point should work.
            // always remain in the journal.
            assert!(matches!(journal.rewind(300).await, Ok(())));
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 300);
            assert!(bounds.is_empty());

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewind_commit_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..12u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");

            journal.rewind(7).await.expect("failed to rewind journal");
            journal.commit().await.expect("failed to commit journal");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.bounds().await, 0..7);
            for i in 0..7u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            assert!(matches!(
                journal.read(7).await,
                Err(Error::ItemOutOfRange(7))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewind_persists_lower_watermark() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..12u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            journal.rewind(7).await.expect("failed to rewind journal");
            drop(journal);

            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let metadata = Metadata::<_, u64, VecU64>::init(context.child("metadata"), meta_cfg)
                .await
                .expect("failed to reopen metadata");
            let persisted_watermark = metadata
                .get(&RECOVERY_WATERMARK_KEY)
                .copied()
                .map(u64::from)
                .expect("missing recovery watermark after rewind");
            assert_eq!(persisted_watermark, 7);
            drop(metadata);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_after_watermark_lowered_before_rewind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..12u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");

            {
                let mut inner = journal.inner.write().await;
                inner.metadata.put(RECOVERY_WATERMARK_KEY, 7u64.into());
                inner
                    .metadata
                    .sync()
                    .await
                    .expect("failed to lower recovery watermark");
            }
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 0..12);
            assert_eq!(journal.recovery_watermark().await, 7);
            assert_eq!(journal.read(11).await.unwrap(), test_digest(11));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewind_append_commit_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..12u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");

            journal.rewind(7).await.expect("failed to rewind journal");
            for i in 0..3u64 {
                journal
                    .append(&test_digest(100 + i))
                    .await
                    .expect("failed to append data");
            }
            journal.commit().await.expect("failed to commit journal");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.bounds().await, 0..10);
            assert_eq!(journal.recovery_watermark().await, 7);
            for i in 0..7u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            for i in 0..3u64 {
                assert_eq!(journal.read(7 + i).await.unwrap(), test_digest(100 + i));
            }
            assert!(matches!(
                journal.read(10).await,
                Err(Error::ItemOutOfRange(10))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_recovery_handles_multiple_empty_data_tail_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(1));
            let journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // Persist a prefix, then append across multiple section boundaries without syncing. The
            // unsynced item bytes are lost on drop, but their section blobs remain visible.
            assert_eq!(journal.append(&test_digest(10)).await.unwrap(), 0);
            journal.sync().await.unwrap();
            assert_eq!(journal.append(&test_digest(20)).await.unwrap(), 1);
            assert_eq!(journal.append(&test_digest(30)).await.unwrap(), 2);
            drop(journal);

            let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
            assert!(
                blobs.len() > 2,
                "expected multiple empty trailing sections, got {}",
                blobs.len()
            );

            let journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..1);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(10));
            drop(journal);

            // Recovery should remove the empty trailing sections, leaving only the durable prefix's
            // section and the recreated tail.
            let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(blobs.len(), 2);

            let journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 1);
            assert_eq!(journal.read(1).await.unwrap(), test_digest(42));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_recovery_handles_empty_data_with_no_durable_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(1));
            let journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // Append across multiple section boundaries without ever syncing. No item bytes become
            // durable, so recovery sees multiple empty sections and no durable data.
            assert_eq!(journal.append(&test_digest(10)).await.unwrap(), 0);
            assert_eq!(journal.append(&test_digest(20)).await.unwrap(), 1);
            drop(journal);

            let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
            assert!(
                blobs.len() > 1,
                "expected multiple empty sections, got {}",
                blobs.len()
            );

            let journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..0);
            drop(journal);

            // Recovery should remove the extra empty sections, leaving only the recreated tail.
            let blobs = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(blobs.len(), 1);

            let journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 0);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(42));
            journal.destroy().await.unwrap();
        });
    }

    /// Test that a crash partway through a multi-section sync leaves a contiguous durable prefix
    /// that recovery preserves.
    ///
    /// `flush_dirty_sections` syncs dirty sections, and all mutating operations serialize on
    /// `op_lock` so no concurrent sync can interleave. This reproduces a crash after sections 0 and
    /// 1 were synced but before section 2, then asserts recovery keeps exactly the contiguous
    /// prefix 0..20.
    #[test_traced]
    fn test_fixed_recovery_partial_sync_loop_keeps_contiguous_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Fill sections 0 and 1 and partially fill section 2 (positions 20..25). Nothing is
            // synced yet, so only the created section blobs are durable, all still empty.
            for i in 0..25u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            // Sync sections 0 and 1 but not section 2, simulating a crash after part of a
            // multi-section sync became durable.
            {
                let inner = journal.inner.write().await;
                inner.journal.sync(0).await.unwrap();
                inner.journal.sync(1).await.unwrap();
            }
            drop(journal);

            // The durable data is exactly the contiguous prefix: sections 0 and 1 hold items and
            // section 2 is an empty trailing blob.
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(names.len(), 3);
            for (section, name) in names.iter().enumerate() {
                let (_blob, size) = context.open(&blob_partition(&cfg), name).await.unwrap();
                if section < 2 {
                    assert!(size > 0, "section {section} should be durable");
                } else {
                    assert_eq!(size, 0, "section {section} should be empty");
                }
            }

            // Recovery preserves exactly the contiguous prefix 0..20.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..20);
            for i in 0..20u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(20))
            ));

            // Appends resume cleanly from the recovered boundary.
            assert_eq!(journal.append(&test_digest(999)).await.unwrap(), 20);
            assert_eq!(journal.read(20).await.unwrap(), test_digest(999));

            journal.destroy().await.unwrap();
        });
    }

    /// Test that a durable section above the sync watermark, sitting beyond an empty intermediate
    /// section, is rolled back to the contiguous boundary during recovery.
    ///
    /// Since #3790 removed the append-time sync when crossing blob boundaries, a process crash can
    /// leave a later section incidentally durable while an earlier section stayed buffered and was
    /// lost, producing a physical gap. Length-based recovery walks sections from oldest and
    /// truncates at the first short non-tail section, so the post-gap section is discarded and only
    /// the synced prefix survives.
    #[test_traced]
    fn test_fixed_recovery_rolls_back_durable_section_after_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Durably commit section 0 (positions 0..10), advancing the recovery watermark to 10.
            for i in 0..10u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Append section 1 and part of section 2 without committing. Manually sync only section
            // 2 to mimic its writes surviving a crash, while section 1 stays buffered and is lost.
            for i in 10..28u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            {
                let inner = journal.inner.write().await;
                inner.journal.sync(2).await.unwrap();
            }
            drop(journal);

            // Durable state: section 0 (10 items), section 1 (empty gap), section 2 (8 items).
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(names.len(), 3);
            let mut sizes = Vec::new();
            for name in &names {
                let (_blob, size) = context.open(&blob_partition(&cfg), name).await.unwrap();
                sizes.push(size);
            }
            assert!(sizes[0] > 0, "section 0 should be durable");
            assert_eq!(sizes[1], 0, "section 1 should be the gap");
            assert!(sizes[2] > 0, "section 2 should be incidentally durable");

            // Recovery rolls back to the watermark boundary: only the synced prefix survives and the
            // gapped section 2 is truncated away.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..10);
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            assert!(matches!(
                journal.read(10).await,
                Err(Error::ItemOutOfRange(10))
            ));

            // The orphaned section 2 is gone; the truncated section 1 remains as the recovered tail.
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(names.len(), 2);

            // Appends resume cleanly from the recovered boundary.
            assert_eq!(journal.append(&test_digest(999)).await.unwrap(), 10);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(999));

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest section is empty but a newer section still holds durable items.
    ///
    /// This is the fixed-journal analog of the variable-journal empty-oldest-section gap bug. A
    /// contiguous journal can only populate a later section after filling the earlier one, so an
    /// empty oldest section with a populated newer section is an orphaned gap. Length-based recovery
    /// walks from the oldest section, finds it short (empty), and truncates everything from there,
    /// aligning the journal to empty without panicking.
    #[test_traced]
    fn test_fixed_recovery_empty_oldest_section_orphaned_newer_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));

            // Durably persist sections 0 and 1 (positions 0..20).
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Empty the oldest section (external corruption). The watermark (20) now exceeds the
            // recoverable size (0), which is corruption.
            let (section0, size0) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .unwrap();
            assert!(size0 > 0);
            section0.resize(0).await.unwrap();
            section0.sync().await.unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Test the contiguous fixed journal with items_per_blob: 1.
    ///
    /// This is an edge case where each item creates its own blob, and the
    /// tail blob is always empty after sync (because the item fills the blob
    /// and a new empty one is created).
    #[test_traced]
    fn test_single_item_per_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "single-item-per-blob".into(),
                items_per_blob: NZU64!(1),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                write_buffer: NZUsize!(2048),
            };

            // === Test 1: Basic single item operation ===
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Verify empty state
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 0);
            assert!(bounds.is_empty());

            // Append 1 item
            let pos = journal
                .append(&test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos, 0);
            assert_eq!(journal.size().await, 1);

            // Sync
            journal.sync().await.expect("failed to sync");

            // Read from size() - 1
            let value = journal
                .read(journal.size().await - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(0));

            // === Test 2: Multiple items with single item per blob ===
            for i in 1..10u64 {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append");
                assert_eq!(pos, i);
                assert_eq!(journal.size().await, i + 1);

                // Verify we can read the just-appended item at size() - 1
                let value = journal
                    .read(journal.size().await - 1)
                    .await
                    .expect("failed to read");
                assert_eq!(value, test_digest(i));
            }

            // Verify all items can be read
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.sync().await.expect("failed to sync");

            // === Test 3: Pruning with single item per blob ===
            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.expect("failed to prune");

            // Size should still be 10
            assert_eq!(journal.size().await, 10);

            // bounds.start should be 5
            assert_eq!(journal.bounds().await.start, 5);

            // Reading from size() - 1 (position 9) should still work
            let value = journal
                .read(journal.size().await - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(9));

            // Reading from pruned positions should return ItemPruned
            for i in 0..5 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            // Reading from retained positions should work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            // Append more items after pruning
            for i in 10..15u64 {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append");
                assert_eq!(pos, i);

                // Verify we can read from size() - 1
                let value = journal
                    .read(journal.size().await - 1)
                    .await
                    .expect("failed to read");
                assert_eq!(value, test_digest(i));
            }

            journal.sync().await.expect("failed to sync");
            drop(journal);

            // === Test 4: Restart persistence with single item per blob ===
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify size is preserved
            assert_eq!(journal.size().await, 15);

            // Verify bounds.start is preserved
            assert_eq!(journal.bounds().await.start, 5);

            // Reading from size() - 1 should work after restart
            let value = journal
                .read(journal.size().await - 1)
                .await
                .expect("failed to read");
            assert_eq!(value, test_digest(14));

            // Reading all retained positions should work
            for i in 5..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 5: Restart after pruning with non-zero index ===
            // Fresh journal for this test
            let journal = Journal::init(context.child("third"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 10 items (positions 0-9)
            for i in 0..10u64 {
                journal.append(&test_digest(i + 100)).await.unwrap();
            }

            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.unwrap();
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 5);

            // Sync and restart
            journal.sync().await.unwrap();
            drop(journal);

            // Re-open journal
            let journal = Journal::<_, Digest>::init(context.child("fourth"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify state after restart
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 5);

            // Reading from size() - 1 (position 9) should work
            let value = journal.read(journal.size().await - 1).await.unwrap();
            assert_eq!(value, test_digest(109));

            // Verify all retained positions (5-9) work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i + 100));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 6: Prune all items (edge case) ===
            let journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..5u64 {
                journal.append(&test_digest(i + 200)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune all items
            journal.prune(5).await.unwrap();
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 5); // Size unchanged
            assert!(bounds.is_empty()); // All pruned

            // size() - 1 = 4, but position 4 is pruned
            let result = journal.read(journal.size().await - 1).await;
            assert!(matches!(result, Err(Error::ItemPruned(4))));

            // After appending, reading works again
            journal.append(&test_digest(205)).await.unwrap();
            assert_eq!(journal.bounds().await.start, 5);
            assert_eq!(
                journal.read(journal.size().await - 1).await.unwrap(),
                test_digest(205)
            );

            journal.destroy().await.expect("failed to destroy journal");
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 0)
                    .await
                    .unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 0);
            assert!(bounds.is_empty());

            // Next append should get position 0
            let pos = journal.append(&test_digest(100)).await.unwrap();
            assert_eq!(pos, 0);
            assert_eq!(journal.size().await, 1);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(100));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_section_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 10 (exactly at section 2 boundary with items_per_blob=5)
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 10)
                    .await
                    .unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 10);
            assert!(bounds.is_empty());

            // Next append should get position 10
            let pos = journal.append(&test_digest(1000)).await.unwrap();
            assert_eq!(pos, 10);
            assert_eq!(journal.size().await, 11);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(1000));

            // Can continue appending
            let pos = journal.append(&test_digest(1001)).await.unwrap();
            assert_eq!(pos, 11);
            assert_eq!(journal.read(11).await.unwrap(), test_digest(1001));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 7 (middle of section 1 with items_per_blob=5)
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 7)
                    .await
                    .unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 7);
            // No data exists yet after init_at_size
            assert!(bounds.is_empty());

            // Reading before bounds.start should return ItemPruned
            assert!(matches!(journal.read(5).await, Err(Error::ItemPruned(5))));
            assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));

            // Next append should get position 7
            let pos = journal.append(&test_digest(700)).await.unwrap();
            assert_eq!(pos, 7);
            assert_eq!(journal.size().await, 8);
            assert_eq!(journal.read(7).await.unwrap(), test_digest(700));
            // Now bounds.start should be 7 (first data position)
            assert_eq!(journal.bounds().await.start, 7);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_append_many_after_mid_section_start() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(100));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 150)
                    .await
                    .unwrap();

            let items: Vec<_> = (0..100u64).map(|i| test_digest(1500 + i)).collect();
            let last = journal.append_many(Many::Flat(&items)).await.unwrap();
            assert_eq!(last, 249);
            assert_eq!(journal.bounds().await, 150..250);

            for (position, index) in [(150, 0), (199, 49), (200, 50), (249, 99)] {
                assert_eq!(
                    journal.read(position).await.unwrap(),
                    items[index],
                    "item at position {position} did not match"
                );
            }

            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 150..250);
            for (position, index) in [(150, 0), (199, 49), (200, 50), (249, 99)] {
                assert_eq!(
                    journal.read(position).await.unwrap(),
                    items[index],
                    "item at position {position} did not match after reopen"
                );
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 15
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 15)
                    .await
                    .unwrap();

            // Append some items
            for i in 0..5u64 {
                let pos = journal.append(&test_digest(1500 + i)).await.unwrap();
                assert_eq!(pos, 15 + i);
            }

            assert_eq!(journal.size().await, 20);

            // Sync and reopen
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Size and data should be preserved
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 20);
            assert_eq!(bounds.start, 15);

            // Verify data
            for i in 0..5u64 {
                assert_eq!(journal.read(15 + i).await.unwrap(), test_digest(1500 + i));
            }

            // Can continue appending
            let pos = journal.append(&test_digest(9999)).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), test_digest(9999));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_persistence_without_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 15
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 15)
                    .await
                    .unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 15);
            assert!(bounds.is_empty());

            // Drop without writing any data
            drop(journal);

            // Reopen and verify size persisted
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 15);
            assert!(bounds.is_empty());

            // Can append starting at position 15
            let pos = journal.append(&test_digest(1500)).await.unwrap();
            assert_eq!(pos, 15);
            assert_eq!(journal.read(15).await.unwrap(), test_digest(1500));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_large_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at a large position (position 1000)
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 1000)
                    .await
                    .unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 1000);
            assert!(bounds.is_empty());

            // Next append should get position 1000
            let pos = journal.append(&test_digest(100000)).await.unwrap();
            assert_eq!(pos, 1000);
            assert_eq!(journal.read(1000).await.unwrap(), test_digest(100000));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 20
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 20)
                    .await
                    .unwrap();

            // Append items 20-29
            for i in 0..10u64 {
                journal.append(&test_digest(2000 + i)).await.unwrap();
            }

            assert_eq!(journal.size().await, 30);

            // Prune to position 25
            journal.prune(25).await.unwrap();

            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 30);
            assert_eq!(bounds.start, 25);

            // Verify remaining items are readable
            for i in 25..30u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(2000 + (i - 20)));
            }

            // Continue appending
            let pos = journal.append(&test_digest(3000)).await.unwrap();
            assert_eq!(pos, 30);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::init(context.child("journal"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 25 items (positions 0-24, spanning 3 blobs)
            for i in 0..25u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 25);
            journal.sync().await.unwrap();

            // Clear to position 100, effectively resetting the journal
            journal.clear_to_size(100).await.unwrap();
            assert_eq!(journal.size().await, 100);

            // Old positions should fail
            for i in 0..25 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            // Verify size persists after restart without writing any data
            drop(journal);
            let journal =
                Journal::<_, Digest>::init(context.child("journal_after_clear"), cfg.clone())
                    .await
                    .expect("failed to re-initialize journal after clear");
            assert_eq!(journal.size().await, 100);

            // Append new data starting at position 100
            for i in 100..105u64 {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, i);
            }
            assert_eq!(journal.size().await, 105);

            // New positions should be readable
            for i in 100..105u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            // Sync and re-init to verify persistence
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("journal_reopened"), cfg)
                .await
                .expect("failed to re-initialize journal");

            assert_eq!(journal.size().await, 105);
            for i in 100..105u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_sync_crash_meta_none_boundary_aligned() {
        // Old meta = None (aligned), new boundary = aligned.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.commit().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 0);
            assert_eq!(bounds.end, 5);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_missing_metadata_with_short_section_is_corruption() {
        // Clearing all metadata leaves no watermark. Recovery falls back to the blob boundary
        // and finds a short non-tail section, violating the legacy rollover-sync invariant.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Simulate metadata deletion (corruption).
            let mut inner = journal.inner.write().await;
            inner.metadata.clear();
            inner.metadata.sync().await.unwrap();
            drop(inner);
            drop(journal);

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_sync_crash_meta_mid_boundary_unchanged() {
        // Old meta = Some(mid), new boundary = mid-section (same value).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.commit().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 7);
            assert_eq!(bounds.end, 10);
            journal.destroy().await.unwrap();
        });
    }
    #[test_traced]
    fn test_fixed_journal_sync_crash_meta_mid_to_aligned_becomes_stale() {
        // Old meta = Some(mid), new boundary = aligned.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..10u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 17);
            journal.prune(10).await.unwrap();

            journal.commit().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 10);
            assert_eq!(bounds.end, 17);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_prune_does_not_move_boundary_backwards() {
        // Pruning to a position earlier than pruning_boundary (within the same section)
        // should not move the boundary backwards.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            // init_at_size(7) sets pruning_boundary = 7 (mid-section in section 1)
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            // Append 5 items at positions 7-11, filling section 1 and part of section 2
            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            // Prune to position 5 (section 1 start) should NOT move boundary back from 7 to 5
            journal.prune(5).await.unwrap();
            assert_eq!(journal.bounds().await.start, 7);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_after_init_at_size_spanning_sections() {
        // Test replay when first section begins mid-section: init_at_size creates a journal
        // where pruning_boundary is mid-section, then we append across multiple sections.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 7 (mid-section with items_per_blob=5)
            // Section 1 (positions 5-9) begins mid-section: only positions 7, 8, 9 have data
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 13 items (positions 7-19), spanning sections 1, 2, 3
            for i in 0..13u64 {
                let pos = journal.append(&test_digest(100 + i)).await.unwrap();
                assert_eq!(pos, 7 + i);
            }
            assert_eq!(journal.size().await, 20);
            journal.sync().await.unwrap();

            // Replay from pruning_boundary
            {
                let reader = journal.reader().await;
                let stream = reader
                    .replay(NZUsize!(1024), 7)
                    .await
                    .expect("failed to replay");
                pin_mut!(stream);
                let mut items: Vec<(u64, Digest)> = Vec::new();
                while let Some(result) = stream.next().await {
                    items.push(result.expect("replay item failed"));
                }

                // Should get all 13 items with correct logical positions
                assert_eq!(items.len(), 13);
                for (i, (pos, item)) in items.iter().enumerate() {
                    assert_eq!(*pos, 7 + i as u64);
                    assert_eq!(*item, test_digest(100 + i as u64));
                }
            }

            // Replay from mid-stream (position 12)
            {
                let reader = journal.reader().await;
                let stream = reader
                    .replay(NZUsize!(1024), 12)
                    .await
                    .expect("failed to replay from mid-stream");
                pin_mut!(stream);
                let mut items: Vec<(u64, Digest)> = Vec::new();
                while let Some(result) = stream.next().await {
                    items.push(result.expect("replay item failed"));
                }

                // Should get items from position 12 onwards
                assert_eq!(items.len(), 8);
                for (i, (pos, item)) in items.iter().enumerate() {
                    assert_eq!(*pos, 12 + i as u64);
                    assert_eq!(*item, test_digest(100 + 5 + i as u64));
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewind_error_before_bounds_start() {
        // Test that rewind returns error when trying to rewind before bounds.start
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 10)
                    .await
                    .unwrap();

            // Append a few items (positions 10, 11, 12)
            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 13);

            // Rewind to position 11 should work
            journal.rewind(11).await.unwrap();
            assert_eq!(journal.size().await, 11);

            // Rewind to position 10 (pruning_boundary) should work
            journal.rewind(10).await.unwrap();
            assert_eq!(journal.size().await, 10);

            // Rewind to before pruning_boundary should fail
            let result = journal.rewind(9).await;
            assert!(matches!(result, Err(Error::InvalidRewind(9))));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_crash_scenarios() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Setup: Create a journal with some data and mid-section metadata
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Crash Scenario 1: after clear intent is synced and blobs are removed, but before
            // the new tail blob is created.
            let blob_part = blob_partition(&cfg);
            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let mut metadata =
                Metadata::<_, u64, VecU64>::init(context.child("intent_meta"), meta_cfg.clone())
                    .await
                    .unwrap();
            metadata.put(CLEAR_TARGET_KEY, 12u64.into());
            metadata.sync().await.unwrap();
            drop(metadata);
            context.remove(&blob_part, None).await.unwrap();

            // Recovery should complete the interrupted init_at_size(12).
            let journal = Journal::<_, Digest>::init(
                context.child("crash").with_attribute("index", 1),
                cfg.clone(),
            )
            .await
            .expect("init failed after clear crash");
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 12);
            assert_eq!(bounds.start, 12);
            drop(journal);

            // Restore metadata for next scenario (it might have been removed by init)
            let mut metadata =
                Metadata::<_, u64, VecU64>::init(context.child("restore_meta"), meta_cfg.clone())
                    .await
                    .unwrap();
            metadata.put(PRUNING_BOUNDARY_KEY, 7u64.into());
            metadata.put(CLEAR_TARGET_KEY, 2u64.into());
            metadata.sync().await.unwrap();
            drop(metadata);

            // Crash Scenario 2: after the new tail blob is created, but before final metadata
            // replaces the clear intent.
            let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap(); // Ensure it exists
            drop(blob);

            // Recovery should complete the interrupted init_at_size(2).
            let journal = Journal::<_, Digest>::init(
                context.child("crash").with_attribute("index", 2),
                cfg.clone(),
            )
            .await
            .expect("init failed after create crash");

            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 2);
            assert_eq!(bounds.end, 2);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size_crash_scenarios() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Setup: Init at 12 (Section 2, offset 2)
            // Metadata = 12
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 12)
                    .await
                    .unwrap();
            journal.sync().await.unwrap();
            drop(journal);

            // Crash Scenario: clear_to_size(2) after the intent is synced and blob 0 is created,
            // but before final metadata replaces the clear intent.

            let blob_part = blob_partition(&cfg);
            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
                .await
                .unwrap();
            metadata.put(CLEAR_TARGET_KEY, 2u64.into());
            metadata.sync().await.unwrap();
            drop(metadata);

            context.remove(&blob_part, None).await.unwrap();

            let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();

            let journal = Journal::<_, Digest>::init(context.child("crash_clear"), cfg.clone())
                .await
                .expect("init failed after clear_to_size crash");

            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 2);
            assert_eq!(bounds.end, 2);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size_crash_after_intent_before_blobs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..12u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
                .await
                .unwrap();
            metadata.put(CLEAR_TARGET_KEY, 100u64.into());
            metadata.sync().await.unwrap();
            drop(metadata);
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("init failed after clear intent crash");
            assert_eq!(journal.bounds().await, 100..100);
            let pos = journal.append(&test_digest(100)).await.unwrap();
            assert_eq!(pos, 100);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size_crash_after_mid_section_intent_with_old_blobs_present() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 10)
                    .await
                    .unwrap();

            for i in 0..6u64 {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, 10 + i);
            }
            journal.sync().await.unwrap();

            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
                .await
                .unwrap();
            metadata.put(CLEAR_TARGET_KEY, 15u64.into());
            metadata.sync().await.unwrap();
            drop(metadata);
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("init failed after mid-section clear intent crash");
            assert_eq!(journal.bounds().await, 15..15);
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .expect("init failed after completing mid-section clear intent");
            assert_eq!(journal.bounds().await, 15..15);
            assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(14))));
            let pos = journal.append(&test_digest(100)).await.unwrap();
            assert_eq!(pos, 15);
            assert_eq!(journal.read(15).await.unwrap(), test_digest(100));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rejects_watermark_with_aligned_empty_tail() {
        // Watermark beyond the recovered size with an aligned pruning boundary.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..10u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Remove all blobs and create a single empty section 1, leaving
            // recovery_watermark=10 in metadata.
            let blob_part = blob_partition(&cfg);
            context.remove(&blob_part, None).await.unwrap();
            let (blob, _) = context.open(&blob_part, &1u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();

            let result = Journal::<_, Digest>::init(context.child("crash"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_rejects_far_watermark_with_aligned_empty_tail() {
        // Same as above but the watermark is multiple sections past the empty tail.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..10u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Remove all blobs and create a single empty section 0, leaving
            // recovery_watermark=10 in metadata.
            let blob_part = blob_partition(&cfg);
            context.remove(&blob_part, None).await.unwrap();
            let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();

            let result = Journal::<_, Digest>::init(context.child("crash"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_read_many_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::<_, Digest>::init(context.child("j"), cfg)
                .await
                .unwrap();

            let items = journal.reader().await.read_many(&[]).await.unwrap();
            assert!(items.is_empty());

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_single_blob() {
        // All positions within one blob.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 5);

            let items = journal.reader().await.read_many(&[0, 2, 4]).await.unwrap();
            assert_eq!(items, vec![test_digest(0), test_digest(2), test_digest(4)]);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_across_blobs() {
        // Positions spanning multiple blobs (items_per_blob=3).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(3));
            let journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..9u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 9);
            // Blobs: [0,1,2], [3,4,5], [6,7,8]

            let items = journal.reader().await.read_many(&[1, 4, 7]).await.unwrap();
            assert_eq!(items, vec![test_digest(1), test_digest(4), test_digest(7)]);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_after_prune() {
        // Read from positions that survive pruning.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(3));
            let journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..9u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 9);
            journal.sync().await.unwrap();

            // Prune first blob [0,1,2].
            journal.prune(3).await.unwrap();
            assert_eq!(journal.bounds().await, 3..9);

            let items = journal.reader().await.read_many(&[3, 5, 8]).await.unwrap();
            assert_eq!(items, vec![test_digest(3), test_digest(5), test_digest(8)]);

            // Pruned position should error.
            let err = journal.reader().await.read_many(&[1]).await.unwrap_err();
            assert!(matches!(err, Error::ItemPruned(1)));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_out_of_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 3);

            let err = journal.reader().await.read_many(&[0, 5]).await.unwrap_err();
            assert!(matches!(err, Error::ItemOutOfRange(5)));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_matches_read() {
        // Verify batch read matches individual reads across blobs.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(4));
            let journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..20u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size().await, 20);
            journal.sync().await.unwrap();

            let positions: Vec<u64> = (0..20).collect();
            let reader = journal.reader().await;
            let batch = reader.read_many(&positions).await.unwrap();

            for &pos in &positions {
                let single = reader.read(pos).await.unwrap();
                assert_eq!(batch[pos as usize], single);
            }
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_sparse_sections_and_hit_accounting() {
        // Verify the batched read path is byte-identical to per-item reads across multiple
        // sections, with a mid-section pruning boundary, a sparse subset of positions, and
        // exact hit/miss accounting over a mixed cached/uncached batch.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(8));
            let journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..50u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            // Prune mid-section so first_in_section differs from section start.
            journal.prune(11).await.unwrap();

            let reader = journal.reader().await;

            fn counter(buffer: &str, name: &str) -> u64 {
                buffer
                    .lines()
                    .find(|l| l.contains(name) && !l.starts_with('#'))
                    .and_then(|l| l.split_whitespace().last())
                    .and_then(|v| v.parse().ok())
                    .expect("counter missing")
            }

            // Sparse subset spanning multiple sections, including the pruning boundary.
            // `try_read_sync` probes do not populate the cache, so the cached subset is
            // whatever the append path left resident; derive the expected hit count from
            // probes so the batch read's hit/miss accounting is asserted exactly.
            let positions: Vec<u64> = vec![11, 12, 19, 20, 23, 31, 40, 47, 49];
            let expected_hits = positions
                .iter()
                .filter(|&&pos| reader.try_read_sync(pos).is_some())
                .count() as u64;
            let before = context.encode();
            let batch = reader.read_many(&positions).await.unwrap();
            let after = context.encode();
            assert_eq!(batch.len(), positions.len());
            assert_eq!(
                counter(&after, "cache_hits") - counter(&before, "cache_hits"),
                expected_hits,
                "batch read hit count should match the cached subset"
            );
            assert_eq!(
                counter(&after, "cache_misses") - counter(&before, "cache_misses"),
                positions.len() as u64 - expected_hits,
                "batch read miss count should cover the rest"
            );
            for (i, &pos) in positions.iter().enumerate() {
                let single = reader.read(pos).await.unwrap();
                assert_eq!(batch[i], single);
                assert_eq!(batch[i], test_digest(pos));
            }

            // Full contiguous range over retained items.
            let all: Vec<u64> = (11..50).collect();
            let batch = reader.read_many(&all).await.unwrap();
            for (i, &pos) in all.iter().enumerate() {
                assert_eq!(batch[i], reader.read(pos).await.unwrap());
            }
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let journal = Journal::<_, Digest>::init(context.child("fixed_metrics"), cfg.clone())
                .await
                .unwrap();

            let items: Vec<_> = (0..5).map(test_digest).collect();
            journal.append_many(Many::Flat(&items)).await.unwrap();
            journal.append(&test_digest(5)).await.unwrap();
            journal.commit().await.unwrap();
            journal.sync().await.unwrap();
            journal.reader().await.read(0).await.unwrap();
            journal.reader().await.try_read_sync(0).unwrap();
            journal.reader().await.read_many(&[1, 2, 4]).await.unwrap();
            journal.prune(2).await.unwrap();
            journal.rewind(4).await.unwrap();

            let buffer = context.encode();
            for expected in [
                "fixed_metrics_size 4",
                "fixed_metrics_pruning_boundary 2",
                "fixed_metrics_retained 2",
                "fixed_metrics_tail_items 2",
                "fixed_metrics_append_calls_total 1",
                "fixed_metrics_append_many_calls_total 1",
                "fixed_metrics_read_calls_total 1",
                "fixed_metrics_read_many_calls_total 1",
                "fixed_metrics_try_read_sync_hits_total 1",
                "fixed_metrics_items_read_total 5",
                "fixed_metrics_commit_calls_total 1",
                "fixed_metrics_sync_calls_total 1",
                "fixed_metrics_append_duration_count 1",
                "fixed_metrics_append_many_duration_count 1",
                "fixed_metrics_read_duration_count 1",
                "fixed_metrics_read_many_duration_count 1",
                "fixed_metrics_commit_duration_count 1",
                "fixed_metrics_sync_duration_count 1",
                "fixed_metrics_cache_hits_total",
                "fixed_metrics_cache_misses_total",
                "fixed_metrics_blobs_tracked",
            ] {
                assert!(buffer.contains(expected), "{expected}\n{buffer}");
            }

            journal.destroy().await.unwrap();
        });
    }
}
