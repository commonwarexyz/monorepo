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
//! Recovery derives fixed-journal size from retained blob lengths:
//! - Once RECOVERY_WATERMARK_KEY exists, recovery walks retained blob lengths from oldest to
//!   newest. A short newest section is the natural tail; a short earlier section is treated as the
//!   end of the contiguous prefix, and newer sections are truncated. After size recovery, the
//!   watermark is preserved if it is still within the recovered size and lowered otherwise.
//! - Legacy journals without RECOVERY_WATERMARK_KEY rely on the old rule that section rollover
//!   synced the previous section. Valid legacy journals recover from the newest retained blob once,
//!   then persist the watermark before returning from `init`.
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
        contiguous::{
            metrics::FixedMetrics as Metrics,
            sections::{Config as SectionsConfig, Sections, SectionsInit},
            Many, Mutable,
        },
        Error,
    },
    metadata::{Config as MetadataConfig, Metadata},
    Context, Persistable,
};
use commonware_codec::{CodecFixedShared, DecodeExt as _, ReadExt as _};
use commonware_runtime::{
    buffer::paged::{CacheRef, Replay},
    Buf, Error as RuntimeError,
};
use commonware_utils::{
    sequence::VecU64,
    sync::{AsyncMutex, AsyncRwLock, AsyncRwLockReadGuard},
};
use futures::{
    future::try_join_all,
    stream::{self, Stream},
    StreamExt,
};
use std::{
    future::Future,
    num::{NonZeroU64, NonZeroUsize},
};
use tracing::warn;

/// Metadata key for a mid-section pruning boundary.
///
/// This key is present only when the oldest retained item is not section-aligned. It is persisted
/// after the blob state it describes exists, so recovery treats it as stale if it no longer matches
/// the oldest retained section.
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
    if pruning_boundary > start {
        Ok(pruning_boundary)
    } else {
        Ok(start)
    }
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
    let skipped = first_in_section(pruning_boundary, section, items_per_blob)?
        .checked_sub(start)
        .ok_or(Error::OffsetOverflow)?;
    items_per_blob
        .checked_sub(skipped)
        .ok_or(Error::OffsetOverflow)
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
    /// The underlying blobs. Historical sections are sealed (immutable, no `RwLock`); only the
    /// tail is writable.
    sections: Sections<E>,

    /// Total number of items appended (not affected by pruning).
    size: u64,

    /// Stores the recovery watermark and, when the pruning boundary is mid-section, the exact
    /// pruning boundary. Also stores an in-progress `CLEAR_TARGET_KEY` while a clear/reset is
    /// running.
    ///
    /// Metadata that advances the pruning boundary or recovery watermark is persisted only after
    /// the blob state it describes is durable. A lower recovery watermark is always safe to persist
    /// because it only expands the suffix external consumers may replay. If pruning metadata
    /// disagrees with the oldest blob during recovery, the blob state wins.
    metadata: Metadata<E, u64, VecU64>,

    /// The position before which all items have been pruned.
    pruning_boundary: u64,

    /// The earliest section modified since the last successful `commit()` or `sync()`.
    dirty_from_section: Option<u64>,

    _phantom: std::marker::PhantomData<A>,
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
        let offset = pos_in_section
            .checked_mul(Journal::<E, A>::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        let bufs = self
            .sections
            .read_at(section, offset, A::SIZE)
            .await
            .map_err(|e| match e {
                Error::SectionOutOfRange(e) | Error::AlreadyPrunedToSection(e) => {
                    Error::Corruption(format!("section/item should be found, but got: {e}"))
                }
                other => other,
            })?;
        A::decode(bufs.coalesce()).map_err(Error::Codec)
    }

    /// Read an item if it can be done synchronously (e.g. without I/O), returning `None` otherwise.
    fn try_read_sync(&self, pos: u64, items_per_blob: u64) -> Option<A> {
        let mut buf = vec![0u8; A::SIZE];
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
        let offset = pos_in_section.checked_mul(Journal::<E, A>::CHUNK_SIZE_U64)?;
        let buf = &mut buf[..A::SIZE];
        if !self.sections.try_read_sync(section, offset, buf) {
            return None;
        }
        A::decode(&buf[..]).ok()
    }
}

/// Implementation of `Journal` storage.
///
/// This is implemented on top of a typed section store that holds historical sections as
/// immutable, sealed views and exposes a single writable tail. Positions are automatically mapped
/// to (section, position_in_section) pairs.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying blob will be truncated to the last valid item). Repair is performed during init.
pub struct Journal<E: Context, A: CodecFixedShared> {
    /// Inner state with the section store and size.
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
        let result = match self.guard.read(pos, self.items_per_blob).await {
            Ok(item) => {
                self.metrics.items_read.inc();
                Ok(item)
            }
            Err(error) => Err(error),
        };
        result
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
        let chunk_size = A::SIZE;
        let chunk_size_u64 = Journal::<E, A>::CHUNK_SIZE_U64;

        // Phase 1: Drain page-cache hits synchronously.
        let mut result: Vec<Option<A>> = Vec::with_capacity(positions.len());
        let mut miss_indices: Vec<usize> = Vec::new();
        let mut miss_positions: Vec<u64> = Vec::new();

        let mut sync_buf = vec![0u8; chunk_size];
        for (i, &pos) in positions.iter().enumerate() {
            if let Some(item) = self
                .guard
                .try_read_sync_into(pos, items_per_blob, &mut sync_buf)
            {
                result.push(Some(item));
            } else {
                result.push(None);
                miss_indices.push(i);
                miss_positions.push(pos);
            }
        }

        if miss_positions.is_empty() {
            self.metrics.record_cache_hits(positions.len() as u64);
            self.metrics.items_read.inc_by(positions.len() as u64);
            return Ok(result.into_iter().map(|r| r.unwrap()).collect());
        }
        self.metrics
            .record_cache_hits((positions.len() - miss_positions.len()) as u64);
        self.metrics
            .record_cache_misses(miss_positions.len() as u64);

        // Phase 2: Read cache misses grouped by section (sequential).
        let mut reusable_buf = vec![0u8; miss_positions.len() * chunk_size];
        let mut disk_offset = 0;

        let mut group_start = 0;
        while group_start < miss_positions.len() {
            let section = miss_positions[group_start] / items_per_blob;

            let mut group_end = group_start + 1;
            while group_end < miss_positions.len()
                && miss_positions[group_end] / items_per_blob == section
            {
                group_end += 1;
            }

            let group_len = group_end - group_start;
            let first_position = first_in_section(pruning_boundary, section, items_per_blob)?;
            let section_offsets: Vec<u64> = miss_positions[group_start..group_end]
                .iter()
                .map(|&pos| {
                    (pos - first_position)
                        .checked_mul(chunk_size_u64)
                        .ok_or(Error::OffsetOverflow)
                })
                .collect::<Result<_, _>>()?;

            let buf = &mut reusable_buf[..group_len * chunk_size];
            self.guard
                .sections
                .read_many_into(section, buf, &section_offsets, chunk_size)
                .await
                .map_err(|e| match e {
                    Error::SectionOutOfRange(e) | Error::AlreadyPrunedToSection(e) => {
                        Error::Corruption(format!("section/item should be found, but got: {e}"))
                    }
                    other => other,
                })?;

            for i in 0..group_len {
                let slice = &buf[i * chunk_size..(i + 1) * chunk_size];
                let item = A::decode(slice).map_err(Error::Codec)?;
                result[miss_indices[disk_offset + i]] = Some(item);
            }

            disk_offset += group_len;
            group_start = group_end;
        }

        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result.into_iter().map(|r| r.unwrap()).collect())
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
        let chunk_size = A::SIZE;
        let chunk_size_u64 = Journal::<E, A>::CHUNK_SIZE_U64;

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
        let sections = &self.guard.sections;
        if let (Some(oldest), Some(newest)) = (sections.oldest_section(), sections.newest_section())
        {
            let first_to_check = oldest
                .checked_add(1)
                .map_or(newest, |after_oldest| start_section.max(after_oldest));
            for section in first_to_check..newest {
                let len = sections.section_size(section).await? / chunk_size_u64;
                if len < items_per_blob {
                    return Err(Error::Corruption(format!(
                        "section {section} incomplete: expected {items_per_blob} items, got {len}"
                    )));
                }
            }
        }

        // Snapshot the sections to iterate over and seed each section's `Replay` upfront so the
        // returned stream borrows nothing from `self` except via the per-section Replays.
        let newest = sections.newest_section();
        let mut per_section_replays: Vec<(u64, Replay<E::Blob>, u64)> = Vec::new();
        if let Some(newest) = newest {
            for section in start_section..=newest {
                let (mut replay, section_size) = sections.replay_section(section, buffer).await?;
                let initial_offset = if section == start_section {
                    let start_byte = start_pos_in_section
                        .checked_mul(chunk_size_u64)
                        .ok_or(Error::OffsetOverflow)?;
                    if start_byte > section_size {
                        return Err(Error::ItemOutOfRange(start_pos));
                    }
                    replay.seek_to(start_byte).map_err(Error::Runtime)?;
                    start_pos_in_section
                } else {
                    0
                };
                per_section_replays.push((section, replay, initial_offset));
            }
        }

        // Concatenate the per-section replays into one stream of `(global position, item)` pairs in
        // ascending position order. Each section is fully drained before the next one starts.
        let stream = stream::iter(per_section_replays).flat_map(
            move |(section, replay, initial_position)| {
                // `unfold` repeatedly calls the closure below, threading `SectionReplayState`
                // through each call, to turn one section's byte `Replay` into a stream of items.
                // Each call returns a *batch* of items (decoding several buffered items per await is
                // cheaper than one await per item); the trailing `flat_map(stream::iter)` then
                // flattens those batches back into a stream of individual items.
                stream::unfold(
                    SectionReplayState {
                        section,
                        replay,
                        position: initial_position,
                        done: false,
                    },
                    move |mut state| async move {
                        // A previous call hit the section's end or an error and set `done`. Returning
                        // `None` terminates this section's stream.
                        if state.done {
                            return None;
                        }

                        let mut batch: Vec<Result<(u64, A), Error>> = Vec::new();
                        loop {
                            // Pull more bytes from the blob until at least one whole item is
                            // buffered (or the section ends / a read fails).
                            match state.replay.ensure(chunk_size).await {
                                // At least one item's worth of bytes is buffered; decode below.
                                Ok(true) => {}
                                // Section fully drained. Emit any items decoded so far, then stop.
                                Ok(false) => {
                                    state.done = true;
                                    return if batch.is_empty() {
                                        None
                                    } else {
                                        Some((batch, state))
                                    };
                                }
                                // Read failure: surface it as the section's final item, then stop.
                                Err(err) => {
                                    batch.push(Err(Error::Runtime(err)));
                                    state.done = true;
                                    return Some((batch, state));
                                }
                            }

                            // Decode every whole item currently buffered.
                            while state.replay.remaining() >= chunk_size {
                                match A::read(&mut state.replay) {
                                    Ok(item) => {
                                        // Translate the item's index within this section into its
                                        // absolute position in the journal.
                                        let global_pos = first_in_section(
                                            pruning_boundary,
                                            state.section,
                                            items_per_blob,
                                        )
                                        .and_then(|first| {
                                            first
                                                .checked_add(state.position)
                                                .ok_or(Error::OffsetOverflow)
                                        });
                                        match global_pos {
                                            Ok(pos) => {
                                                batch.push(Ok((pos, item)));
                                                state.position += 1;
                                            }
                                            // Position overflow: emit the error and stop.
                                            Err(err) => {
                                                batch.push(Err(err));
                                                state.done = true;
                                                return Some((batch, state));
                                            }
                                        }
                                    }
                                    // Corrupt bytes: surface the decode error and stop the section.
                                    Err(err) => {
                                        batch.push(Err(Error::Codec(err)));
                                        state.done = true;
                                        return Some((batch, state));
                                    }
                                }
                            }

                            // Yield the decoded items. `ensure(chunk_size)` returning `Ok(true)`
                            // guarantees we decoded at least one, so `batch` is non-empty here; the
                            // guard simply keeps the loop from yielding an empty batch.
                            if !batch.is_empty() {
                                return Some((batch, state));
                            }
                        }
                    },
                )
                .flat_map(stream::iter)
            },
        );

        Ok(stream)
    }
}

/// State threaded through the `unfold` that replays a single section's blob.
struct SectionReplayState<B: commonware_runtime::Blob> {
    /// The section being replayed.
    section: u64,
    /// Sequential reader over the section's logical bytes.
    replay: Replay<B>,
    /// Index of the next item to emit, relative to the section's first retained item. Added to the
    /// section's first position to recover the item's absolute journal position.
    position: u64,
    /// Set once the section is exhausted or an error was emitted; the next call returns `None`.
    done: bool,
}

impl<E: Context, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry in bytes.
    pub const CHUNK_SIZE: usize = A::SIZE;

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

    /// Stage pruning-boundary and recovery-watermark entries into `metadata`'s in-memory state.
    ///
    /// Only writes when a value actually changes. The caller is responsible for syncing.
    fn stage_metadata_entries(
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
        Ok(Metadata::<_, u64, VecU64>::init(context, meta_cfg).await?)
    }

    /// Scan a partition and return blob names, treating a missing partition as empty.
    async fn scan_partition(context: &E, partition: &str) -> Result<Vec<Vec<u8>>, Error> {
        match context.scan(partition).await {
            Ok(blobs) => Ok(blobs),
            Err(RuntimeError::PartitionMissing(_)) => Ok(Vec::new()),
            Err(err) => Err(Error::Runtime(err)),
        }
    }

    /// Remove a blob partition before completing a staged clear intent.
    async fn remove_blob_partition(context: &E, partition: &str) -> Result<(), Error> {
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
        sections: &mut Sections<E>,
        metadata: &mut Metadata<E, u64, VecU64>,
        items_per_blob: u64,
        size: u64,
    ) -> Result<(), Error> {
        sections.clear().await?;
        sections.install_tail(size / items_per_blob).await?;
        Self::stage_pruning_boundary_metadata(metadata, items_per_blob, size);
        metadata.put(RECOVERY_WATERMARK_KEY, size.into());
        metadata.remove(&CLEAR_TARGET_KEY);
        metadata.sync().await?;
        Ok(())
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

        // A staged clear intent means all old blob data is about to be discarded. Honor it before
        // scanning or opening sections so corrupt stale blobs cannot block recovery of the reset.
        if let Some(clear_target) = metadata.get(&CLEAR_TARGET_KEY).copied().map(u64::from) {
            warn!(clear_target, "crash repair: completing interrupted clear");
            let new_partition = format!("{}-blobs", cfg.partition);
            Self::remove_blob_partition(&context, &cfg.partition).await?;
            Self::remove_blob_partition(&context, &new_partition).await?;
            let tail_section = clear_target / items_per_blob;
            let sections_cfg = SectionsConfig {
                partition: new_partition,
                page_cache: cfg.page_cache,
                write_buffer: cfg.write_buffer,
            };
            let init = SectionsInit::open(context.child("blobs"), sections_cfg).await?;
            let sections = init.reset(tail_section).await?;
            Self::stage_pruning_boundary_metadata(&mut metadata, items_per_blob, clear_target);
            metadata.put(RECOVERY_WATERMARK_KEY, clear_target.into());
            metadata.remove(&CLEAR_TARGET_KEY);
            metadata.sync().await?;

            let inner = Inner {
                sections,
                size: clear_target,
                metadata,
                pruning_boundary: clear_target,
                dirty_from_section: None,
                _phantom: std::marker::PhantomData,
            };
            let metrics = Metrics::new(context);
            metrics.update(clear_target, clear_target, items_per_blob);
            return Ok(Self {
                inner: AsyncRwLock::new(inner),
                op_lock: AsyncMutex::new(()),
                items_per_blob,
                metrics,
            });
        }

        let blob_partition = Self::select_blob_partition(&context, &cfg).await?;
        let sections_cfg = SectionsConfig {
            partition: blob_partition,
            page_cache: cfg.page_cache,
            write_buffer: cfg.write_buffer,
        };

        let mut init = SectionsInit::open(context.child("blobs"), sections_cfg).await?;

        // Truncate any trailing non-chunk-aligned bytes on every section before recovery. Items
        // are fixed size, so a section ending in fewer than `CHUNK_SIZE` trailing bytes is junk
        // from an incomplete write (Append's page-CRC layer surfaces it as a partial logical
        // tail). `SectionsInit::truncate_section` syncs the repair before
        // `recover_bounds` queries lengths.
        let sections_to_check: Vec<u64> = init.sections();
        for section in sections_to_check {
            let size = init.section_size(section).await?;
            if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
                let valid_size = size - (size % Self::CHUNK_SIZE_U64);
                warn!(
                    section,
                    invalid_size = size,
                    new_size = valid_size,
                    "trailing bytes detected: truncating"
                );
                init.truncate_section(section, valid_size).await?;
            }
        }

        let meta_pruning_boundary = metadata.get(&PRUNING_BOUNDARY_KEY).copied().map(u64::from);
        let meta_recovery_watermark = metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from);

        let (pruning_boundary, size, recovery_watermark, repair) = Self::recover_bounds(
            &init,
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

        // Apply repair (if any). The repair section becomes the new tail; sections strictly newer
        // than it are removed. `SectionsInit::truncate_section` (which calls `Append::resize`)
        // syncs the section, so the repair is durable before `into_sections` runs.
        let tail_section = size / items_per_blob;
        if let Some(repair) = repair {
            if repair.section != tail_section {
                return Err(Error::Corruption(format!(
                    "recovery repair target {} != tail section {tail_section}",
                    repair.section
                )));
            }
            // Remove any sections strictly newer than the repair section (newest-first).
            let newer: Vec<u64> = init
                .sections()
                .into_iter()
                .filter(|&s| s > repair.section)
                .rev()
                .collect();
            for s in newer {
                init.remove_section(s).await?;
            }
            init.truncate_section(repair.section, repair.byte_offset)
                .await?;
        }

        let sections = init.into_sections(Some(tail_section)).await?;

        let inner = Inner {
            sections,
            size,
            metadata,
            pruning_boundary,
            dirty_from_section: None,
            _phantom: std::marker::PhantomData,
        };

        let metrics = Metrics::new(context);
        metrics.update(size, pruning_boundary, items_per_blob);

        Ok(Self {
            inner: AsyncRwLock::new(inner),
            op_lock: AsyncMutex::new(()),
            items_per_blob,
            metrics,
        })
    }

    /// Stage pruning-boundary and recovery-watermark entries directly into raw metadata and
    /// persist them. Used by [`Self::init`] before constructing `Inner`.
    async fn persist_metadata_entries_raw(
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
    /// Any in-progress `CLEAR_TARGET_KEY` is completed by the caller before this runs, so the
    /// remaining staleness modes are limited to mismatched pruning metadata. The `repair` is a
    /// blob truncation the caller applies after persisting the lowered checkpoint.
    async fn recover_bounds(
        init: &SectionsInit<E>,
        items_per_blob: u64,
        meta_pruning_boundary: Option<u64>,
        meta_recovery_watermark: Option<u64>,
    ) -> Result<(u64, u64, u64, Option<RecoveryRepair>), Error> {
        let blob_boundary = match init.oldest_section() {
            Some(oldest) => oldest
                .checked_mul(items_per_blob)
                .ok_or(Error::OffsetOverflow)?,
            None => 0,
        };

        // Determine the pruning boundary from metadata and blob state.
        //
        // PRUNING_BOUNDARY_KEY is only stored when the boundary falls mid-section. If present and
        // it refers to the current oldest section, use it. If it refers to a different section
        // (crash left stale metadata), fall back to the section-aligned blob boundary. Absence of
        // the key just means the boundary is section-aligned.
        //
        // Staleness detection is one-sided: we can only tell metadata is stale when it names a
        // section that no longer exists. If it names the current oldest section, we trust it. This
        // is safe because prune persists metadata after blob state, so a crash before the metadata
        // update means the newer boundary was never fully committed.
        let mut pruning_metadata_stale = false;
        let pruning_boundary = match meta_pruning_boundary {
            Some(meta_pruning_boundary)
                if !meta_pruning_boundary.is_multiple_of(items_per_blob) =>
            {
                let meta_oldest_section = meta_pruning_boundary / items_per_blob;
                match init.oldest_section() {
                    None => {
                        warn!(
                            meta_oldest_section,
                            "crash repair: no blobs exist, ignoring stale pruning metadata"
                        );
                        pruning_metadata_stale = true;
                        blob_boundary
                    }
                    Some(oldest_section) if meta_oldest_section < oldest_section => {
                        warn!(
                            meta_oldest_section,
                            oldest_section,
                            "crash repair: pruning metadata stale, computing from blobs"
                        );
                        pruning_metadata_stale = true;
                        blob_boundary
                    }
                    Some(oldest_section) if meta_oldest_section > oldest_section => {
                        warn!(
                            meta_oldest_section,
                            oldest_section,
                            "crash repair: pruning metadata ahead of blobs, computing from blobs"
                        );
                        pruning_metadata_stale = true;
                        blob_boundary
                    }
                    Some(_) => meta_pruning_boundary,
                }
            }
            _ => blob_boundary,
        };

        // Check oldest section for over-capacity corruption before recovery mode dispatch.
        Self::validate_oldest_section(init, items_per_blob, pruning_boundary).await?;

        // Perform any recovery if needed, computing journal size and recovery watermark.
        let (size, repair) = match meta_recovery_watermark {
            Some(_) => {
                Self::recover_by_walking_lengths(init, items_per_blob, pruning_boundary).await?
            }
            None if !pruning_metadata_stale => {
                // No stale pruning metadata and no recovery watermark implies a legacy format.
                Self::recover_legacy_size(init, items_per_blob, pruning_boundary).await?
            }
            None => {
                // Pruning metadata was stale, and there is no recovery watermark to preserve.
                Self::recover_by_walking_lengths(init, items_per_blob, pruning_boundary).await?
            }
        };
        let recovery_watermark = meta_recovery_watermark.unwrap_or(size).min(size);

        Ok((pruning_boundary, size, recovery_watermark, repair))
    }

    /// Check that the oldest section does not exceed its logical capacity.
    async fn validate_oldest_section(
        init: &SectionsInit<E>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) -> Result<(), Error> {
        let Some(oldest) = init.oldest_section() else {
            return Ok(());
        };

        let oldest_len = init.section_size(oldest).await? / Self::CHUNK_SIZE_U64;
        let expected = section_capacity(pruning_boundary, oldest, items_per_blob)?;

        if oldest_len > expected {
            return Err(Error::Corruption(format!(
                "oldest section {oldest} has too many items: expected at most {expected}, got {oldest_len}"
            )));
        }

        Ok(())
    }

    async fn section_len_within_capacity(
        init: &SectionsInit<E>,
        items_per_blob: u64,
        pruning_boundary: u64,
        section: u64,
    ) -> Result<(u64, u64), Error> {
        let len = init.section_size(section).await? / Self::CHUNK_SIZE_U64;
        let capacity = section_capacity(pruning_boundary, section, items_per_blob)?;
        if len > capacity {
            return Err(Error::Corruption(format!(
                "section {section} has too many items: expected at most {capacity}, got {len}"
            )));
        }
        Ok((len, capacity))
    }

    /// Recover a legacy journal that has no RECOVERY_WATERMARK_KEY.
    ///
    /// Before the watermark key existed, writers synced each section before rolling over to the
    /// next one. That lets valid legacy journals recover from the newest retained blob without
    /// walking all retained sections. If the oldest non-tail section is already short, the legacy
    /// invariant is violated and recovery keeps only the contiguous prefix.
    async fn recover_legacy_size(
        init: &SectionsInit<E>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) -> Result<(u64, Option<RecoveryRepair>), Error> {
        let Some(newest) = init.newest_section() else {
            return Ok((pruning_boundary, None));
        };
        let Some(oldest) = init.oldest_section() else {
            return Ok((pruning_boundary, None));
        };

        let (oldest_len, oldest_capacity) =
            Self::section_len_within_capacity(init, items_per_blob, pruning_boundary, oldest)
                .await?;
        if oldest != newest && oldest_len < oldest_capacity {
            // This cannot be a valid legacy state under the old rollover-sync rule, but walking
            // lengths still recovers the contiguous prefix without trusting the stale size.
            return Self::recover_by_walking_lengths(init, items_per_blob, pruning_boundary).await;
        }

        let (tail_len, _) =
            Self::section_len_within_capacity(init, items_per_blob, pruning_boundary, newest)
                .await?;
        let size = first_in_section(pruning_boundary, newest, items_per_blob)?
            .checked_add(tail_len)
            .ok_or(Error::OffsetOverflow)?;
        Ok((size, None))
    }

    /// Recover by walking section lengths until the first short non-tail section.
    ///
    /// This is the normal current-format crash-repair path. Legacy recovery uses it only when the
    /// old rollover invariant is already violated or pruning metadata was stale.
    async fn recover_by_walking_lengths(
        init: &SectionsInit<E>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) -> Result<(u64, Option<RecoveryRepair>), Error> {
        let oldest = init.oldest_section();
        let newest = init.newest_section();

        let (Some(oldest), Some(newest)) = (oldest, newest) else {
            return Ok((pruning_boundary, None));
        };

        // The oldest section's capacity was already checked before recovery mode dispatch.
        let oldest_len = init.section_size(oldest).await? / Self::CHUNK_SIZE_U64;
        let expected_oldest = section_capacity(pruning_boundary, oldest, items_per_blob)?;
        let mut size = pruning_boundary
            .checked_add(oldest_len)
            .ok_or(Error::OffsetOverflow)?;

        if oldest == newest {
            return Ok((size, None));
        }

        if oldest_len < expected_oldest {
            return Ok((
                size,
                Some(RecoveryRepair {
                    section: oldest,
                    byte_offset: oldest_len
                        .checked_mul(Self::CHUNK_SIZE_U64)
                        .ok_or(Error::OffsetOverflow)?,
                }),
            ));
        }

        let sections = init.sections();
        let section_count = sections.len();
        let mut expected = oldest.checked_add(1);
        for (idx, section) in sections.into_iter().enumerate().skip(1) {
            let Some(expected_section) = expected else {
                return Err(Error::Corruption(format!(
                    "section {section} follows terminal section {oldest}"
                )));
            };
            if section < expected_section {
                return Err(Error::Corruption(format!(
                    "section ids out of order: expected at least {expected_section}, got {section}"
                )));
            }
            if section > expected_section {
                return Ok((
                    size,
                    Some(RecoveryRepair {
                        section: expected_section,
                        byte_offset: 0,
                    }),
                ));
            }

            let (len, capacity) =
                Self::section_len_within_capacity(init, items_per_blob, pruning_boundary, section)
                    .await?;

            size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
            if len < capacity {
                if idx + 1 == section_count {
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
            expected = section.checked_add(1);
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
                .sections
                .oldest_section()
                .map(|oldest| start_section.max(oldest))
                // With no retained blobs, any earlier dirty section was cleared or pruned.
                // Syncing the tail section is harmless when it does not exist.
                .unwrap_or(tail_section);
            try_join_all(
                (start_section..=tail_section).map(|section| inner.sections.sync_section(section)),
            )
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
        Self::stage_metadata_entries(
            &mut inner.metadata,
            self.items_per_blob,
            pruning_boundary,
            size,
        );
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
        if items.is_empty() {
            return Err(Error::EmptyAppend);
        }

        // Encode all items into a single contiguous buffer before taking the write guard.
        // Uses Write::write directly to avoid per-item Bytes allocations from Encode::encode.
        let items_count = match &items {
            Many::Flat(items) => items.len(),
            Many::Nested(nested_items) => nested_items.iter().map(|s| s.len()).sum(),
        };
        let mut items_buf = Vec::with_capacity(items_count * A::SIZE);
        match &items {
            Many::Flat(items) => {
                for item in *items {
                    item.write(&mut items_buf);
                }
            }
            Many::Nested(nested_items) => {
                for items in *nested_items {
                    for item in *items {
                        item.write(&mut items_buf);
                    }
                }
            }
        }

        let _op_guard = self.op_lock.lock().await;
        let mut inner = self.inner.write().await;
        let first_dirty_section = inner.size / self.items_per_blob;
        Self::mark_dirty_from(&mut inner, first_dirty_section);
        let mut written = 0;
        while written < items_count {
            let (section, pos_in_section) = self.position_to_section(inner.size);
            let remaining_space = (self.items_per_blob - pos_in_section) as usize;
            let batch_count = remaining_space.min(items_count - written);
            let start = written * A::SIZE;
            let end = start + batch_count * A::SIZE;
            let new_size = inner
                .size
                .checked_add(batch_count as u64)
                .ok_or(Error::OffsetOverflow)?;
            let next_section = if new_size.is_multiple_of(self.items_per_blob) {
                Some(section.checked_add(1).ok_or(Error::OffsetOverflow)?)
            } else {
                None
            };

            inner
                .sections
                .append_to_tail(&items_buf[start..end])
                .await?;
            inner.size = new_size;
            written += batch_count;

            if let Some(next_section) = next_section {
                // Seal the just-filled tail and open the next section as the new tail. This does
                // NOT fsync the old section -- dirty tracking still covers it until commit/sync.
                inner.sections.roll_tail(next_section).await?;
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
    /// * This operation is not atomic. Its on-disk updates are ordered (sections removed
    ///   newest-to-oldest) so that restart recovery always rebuilds a contiguous retained prefix.
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
        inner.sections.rewind(section, byte_offset).await?;
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

        let pruned = inner.sections.prune(min_section).await?;

        // After pruning, update pruning_boundary to the start of the oldest remaining section
        if pruned {
            let new_oldest = inner
                .sections
                .oldest_section()
                .expect("all sections pruned - violates tail section invariant");
            let new_boundary = new_oldest
                .checked_mul(self.items_per_blob)
                .ok_or(Error::OffsetOverflow)?;
            // Pruning boundary only moves forward
            if inner.pruning_boundary >= new_boundary {
                return Err(Error::Corruption(format!(
                    "pruning boundary {} not before new oldest section boundary {new_boundary}",
                    inner.pruning_boundary
                )));
            }
            inner.pruning_boundary = new_boundary;
            if let Some(dirty_from) = inner.dirty_from_section {
                inner.dirty_from_section = Some(dirty_from.max(new_oldest));
            }
            self.metrics
                .update(inner.size, inner.pruning_boundary, self.items_per_blob);
        }

        Ok(pruned)
    }

    /// Remove any persisted data created by the journal.
    pub async fn destroy(self) -> Result<(), Error> {
        // Destroy section blobs and the blob partition itself.
        let inner = self.inner.into_inner();
        inner.sections.destroy().await?;

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
            sections, metadata, ..
        } = &mut *inner;
        Self::complete_clear_to_size(sections, metadata, self.items_per_blob, new_size).await?;

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
        inner.metadata.sync().await?;
        Ok(())
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

    /// Test helper: Get the oldest section from the section store.
    #[cfg(test)]
    pub(crate) async fn test_oldest_section(&self) -> Option<u64> {
        let inner = self.inner.read().await;
        inner.sections.oldest_section()
    }

    /// Test helper: Get the newest section from the section store.
    #[cfg(test)]
    pub(crate) async fn test_newest_section(&self) -> Option<u64> {
        let inner = self.inner.read().await;
        inner.sections.newest_section()
    }

    /// Test helper: Set and persist the recovery watermark directly.
    #[cfg(test)]
    pub(crate) async fn test_set_recovery_watermark(&self, watermark: u64) -> Result<(), Error> {
        let mut inner = self.inner.write().await;
        inner.metadata.put(RECOVERY_WATERMARK_KEY, watermark.into());
        inner.metadata.sync().await?;
        Ok(())
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
}

impl<E: Context, A: CodecFixedShared> Persistable for Journal<E, A> {
    type Error = Error;

    async fn commit(&self) -> Result<(), Error> {
        self.commit().await
    }

    async fn sync(&self) -> Result<(), Error> {
        self.sync().await
    }

    async fn destroy(self) -> Result<(), Error> {
        self.destroy().await
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
        buffer::paged::Append,
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
            assert_eq!(
                journal.inner.read().await.sections.oldest_section(),
                Some(1)
            );
            assert_eq!(
                journal.inner.read().await.sections.newest_section(),
                Some(5)
            );
            assert_eq!(journal.bounds().await.start, 2);

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob.get())
                .await
                .expect("failed to prune journal 2");
            assert_eq!(
                journal.inner.read().await.sections.oldest_section(),
                Some(3)
            );
            assert_eq!(
                journal.inner.read().await.sections.newest_section(),
                Some(5)
            );
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
    fn test_fixed_journal_init_with_corrupted_historical_blobs() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
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
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate a non-tail blob. Recovery should keep the contiguous prefix up to
            // the shortened section and discard newer sections.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            let expected_size = 40 * ITEMS_PER_BLOB.get() + 6;
            assert_eq!(journal.bounds().await, 0..expected_size);
            assert_eq!(journal.recovery_watermark().await, expected_size);
            assert_eq!(journal.test_newest_section().await, Some(40));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_with_missing_historical_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0u64..5 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            drop(journal);

            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .expect("failed to remove blob");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 0..2);
            assert_eq!(journal.recovery_watermark().await, 2);
            assert!(matches!(
                journal.read(2).await,
                Err(Error::ItemOutOfRange(2))
            ));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_test_trim_blob() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();
        // Start the test within the executor
        const ITEMS_PER_BLOB: NonZeroU64 = NZU64!(7);
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 7 items per blob.
            let cfg = test_cfg(&context, ITEMS_PER_BLOB);
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Fill one blob and put 3 items in the second.
            let item_count = ITEMS_PER_BLOB.get() + 3;
            for i in 0u64..item_count {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size().await, item_count);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Truncate the tail blob by one byte, which should result in the last item being
            // discarded during replay (detected via corruption).
            let (blob, size) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // The truncation invalidates the last page (bad checksum), which is removed.
            // This loses one item.
            assert_eq!(journal.size().await, item_count - 1);

            // Cleanup.
            journal.destroy().await.expect("Failed to destroy journal");
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
    fn test_fixed_journal_recover_from_partial_write() {
        // Initialize the deterministic context
        let executor = deterministic::Runner::default();

        // Start the test within the executor
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 3 items per blob.
            let cfg = test_cfg(&context, NZU64!(3));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0..5 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size().await, 5);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // truncate the most recent blob by 1 byte which corrupts the most recent item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");
            // The truncation invalidates the last page, which is removed. This loses one item.
            assert_eq!(journal.pruning_boundary().await, 0);
            assert_eq!(journal.size().await, 4);
            assert_eq!(journal.recovery_watermark().await, 4);
            drop(journal);

            // Delete the second blob and re-init. Recovery keeps the contiguous prefix.
            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .expect("Failed to remove blob");

            let journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .expect("Failed to recover journal");
            assert_eq!(journal.bounds().await, 0..3);
            assert_eq!(journal.recovery_watermark().await, 3);
            assert!(matches!(
                journal.read(3).await,
                Err(Error::ItemOutOfRange(3))
            ));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_persists_trailing_item_repair() {
        let executor = deterministic::Runner::default();
        let ((blob_partition, expected_size), checkpoint) =
            executor.start_and_recover(|context| async move {
                let cfg = test_cfg(&context, NZU64!(5));
                let blob_partition = blob_partition(&cfg);
                let journal = Journal::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();

                for i in 0..3 {
                    journal.append(&test_digest(i)).await.unwrap();
                }
                journal.sync().await.unwrap();
                drop(journal);

                let (blob, raw_size) = context
                    .open(&blob_partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let append = Append::new(
                    blob,
                    raw_size,
                    2048,
                    CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                )
                .await
                .unwrap();
                let logical_size = append.size().await;
                assert_eq!(logical_size, 3 * Digest::SIZE as u64);
                append.resize(logical_size - 1).await.unwrap();
                append.sync().await.unwrap();
                drop(append);

                let journal = Journal::<_, Digest>::init(context.child("second"), cfg)
                    .await
                    .unwrap();
                assert_eq!(journal.size().await, 2);
                drop(journal);

                (blob_partition, 2 * Digest::SIZE as u64)
            });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            let (blob, raw_size) = context
                .open(&blob_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            let append = Append::new(
                blob,
                raw_size,
                2048,
                CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
            )
            .await
            .unwrap();
            assert_eq!(append.size().await, expected_size);
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_accepts_clean_short_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Set up via the public API: 5 items in section 0 (full) + 2 items in section 1
            // (partial), then sync and drop.
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..7 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen and verify the size is exactly 7 with no repair (a clean short tail).
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size().await, 7);
            // Sections 0 and 1 exist and we can read every position.
            for i in 0..7u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_accepts_clean_empty_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Set up via the public API: 5 items in section 0 (full); rolling over implicitly
            // creates an empty section 1 as the tail. Sync and drop.
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..5 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen: section 0 is full, section 1 is the empty tail. Size = 5, no repair.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size().await, 5);
            for i in 0..5u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            assert_eq!(journal.test_newest_section().await, Some(1));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_sparse_section_ids_repairs_at_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(1));
            let blob_partition = blob_partition(&cfg);

            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            journal.append(&test_digest(0)).await.unwrap();
            journal.sync().await.unwrap();
            drop(journal);

            // Add a far-future section directly. Recovery should inspect actual section ids and
            // repair at the first missing boundary instead of walking the entire numeric range.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let (blob, blob_size) = context
                .open(&blob_partition, &u64::MAX.to_be_bytes())
                .await
                .unwrap();
            let append = Append::new(blob, blob_size, 2048, cache_ref).await.unwrap();
            let extra = test_digest(999);
            append.append(extra.as_ref()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..1);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(0));
            assert!(matches!(
                journal.read(1).await,
                Err(Error::ItemOutOfRange(1))
            ));
            assert_eq!(journal.test_newest_section().await, Some(1));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_truncates_short_oldest_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .expect("failed to initialize journal at size");

            // Append items so section 1 has exactly the expected minimum (3 items).
            for i in 0..8u64 {
                journal
                    .append(&test_digest(100 + i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            assert_eq!(journal.pruning_boundary().await, 7);
            assert_eq!(journal.size().await, 15);
            drop(journal);

            // Corrupt the oldest section by truncating one byte (drops one item on recovery).
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
            assert_eq!(journal.recovery_watermark().await, 9);
            assert_eq!(journal.read(7).await.unwrap(), test_digest(100));
            assert_eq!(journal.read(8).await.unwrap(), test_digest(101));
            assert!(matches!(
                journal.read(9).await,
                Err(Error::ItemOutOfRange(9))
            ));
            journal.destroy().await.unwrap();
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
                    .expect("failed to sync stale recovery watermark");
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
            assert_eq!(
                journal.inner.read().await.sections.newest_section(),
                Some(1)
            );

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

            // Stage the stale forward-looking watermark while the journal is alive (so we go
            // through the public metadata path), then drop and corrupt the underlying blob.
            {
                let mut inner = journal.inner.write().await;
                inner.metadata.put(RECOVERY_WATERMARK_KEY, 12u64.into());
                inner
                    .metadata
                    .sync()
                    .await
                    .expect("failed to sync recovery watermark");
            }
            drop(journal);

            // Shorten section 2 to two items via Append::resize so the on-disk logical view
            // matches the staged watermark of 12.
            {
                let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
                let (blob, blob_size) = context
                    .open(&blob_partition(&cfg), &2u64.to_be_bytes())
                    .await
                    .expect("failed to open section 2");
                let append = Append::new(blob, blob_size, 2048, cache_ref)
                    .await
                    .expect("failed to wrap section 2");
                append
                    .resize(2 * Digest::SIZE as u64)
                    .await
                    .expect("failed to shorten anchored section");
                append.sync().await.expect("failed to sync section 2");
            }

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
            assert_eq!(journal.recovery_watermark().await, 17);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
            assert_eq!(journal.read(16).await.unwrap(), test_digest(9));
            assert!(matches!(
                journal.read(17).await,
                Err(Error::ItemOutOfRange(17))
            ));

            journal.destroy().await.unwrap();
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

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover legacy journal");
            assert_eq!(journal.bounds().await, 0..12);
            assert_eq!(journal.recovery_watermark().await, 12);
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
                .expect("missing recovery watermark after legacy recovery");
            assert_eq!(persisted_watermark, 12);
            drop(metadata);

            let journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .expect("failed to reopen upgraded journal");
            assert_eq!(journal.bounds().await, 0..12);
            assert_eq!(journal.recovery_watermark().await, 12);

            journal.destroy().await.unwrap();
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
    fn test_fixed_journal_commit_does_not_advance_recovery_watermark() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            journal.append(&test_digest(0)).await.unwrap();
            journal.sync().await.unwrap();
            assert_eq!(journal.recovery_watermark().await, 1);

            journal.append(&test_digest(1)).await.unwrap();
            journal.commit().await.unwrap();
            assert_eq!(
                journal.recovery_watermark().await,
                1,
                "commit must make dirty sections durable without advancing the recovery watermark",
            );

            journal.sync().await.unwrap();
            assert_eq!(journal.recovery_watermark().await, 2);
            journal.destroy().await.unwrap();
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
            drop(journal);

            // Inject an extra item into section 0 at the blob level so its length exceeds
            // items_per_blob -- this is what `recover_bounds` validates and rejects as Corruption.
            {
                let extra = test_digest(99);
                let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
                let (blob, blob_size) = context
                    .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                    .await
                    .expect("failed to open section 0");
                let append = Append::new(blob, blob_size, 2048, cache_ref)
                    .await
                    .expect("failed to wrap section 0");
                append
                    .append(extra.as_ref())
                    .await
                    .expect("failed to append extra item");
                append
                    .sync()
                    .await
                    .expect("failed to sync corrupted section");
            }

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_truncates_short_middle_before_watermark() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..15u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            journal.sync().await.expect("failed to sync journal");
            assert_eq!(journal.recovery_watermark().await, 15);
            drop(journal);

            // Shorten section 1 to 4 items via blob-level Append::resize.
            {
                let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
                let (blob, blob_size) = context
                    .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                    .await
                    .expect("failed to open section 1");
                let append = Append::new(blob, blob_size, 2048, cache_ref)
                    .await
                    .expect("failed to wrap section 1");
                append
                    .resize(4 * Digest::SIZE as u64)
                    .await
                    .expect("failed to shorten middle section");
                append
                    .sync()
                    .await
                    .expect("failed to sync shortened middle section");
            }

            // Remove the empty tail so the watermark points beyond newest. Recovery now keeps the
            // contiguous prefix up to the short section and lowers the watermark.
            context
                .remove(&blob_partition(&cfg), Some(&3u64.to_be_bytes()))
                .await
                .expect("failed to remove tail section");

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 0..9);
            assert_eq!(journal.recovery_watermark().await, 9);
            assert_eq!(journal.read(8).await.unwrap(), test_digest(8));
            assert!(matches!(
                journal.read(9).await,
                Err(Error::ItemOutOfRange(9))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_to_empty_from_partial_write() {
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

            // Manually truncate most recent blob to simulate a partial write.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            // Truncate the most recent blob by 1 byte which corrupts the one appended item
            blob.resize(size - 1).await.expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal to simulate a restart
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Since there was only a single item appended which we then corrupted, recovery should
            // leave us in the state of an empty journal.
            let bounds = journal.bounds().await;
            assert_eq!(bounds.end, 0);
            assert!(bounds.is_empty());
            assert_eq!(journal.recovery_watermark().await, 0);
            // Make sure journal still works for appending.
            journal
                .append(&test_digest(0))
                .await
                .expect("failed to append data");
            assert_eq!(journal.size().await, 1);

            journal.destroy().await.unwrap();
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

    /// Test recovery when blob is truncated to a page boundary with item size not dividing page size.
    ///
    /// This tests the scenario where:
    /// 1. Items (32 bytes) don't divide evenly into page size (44 bytes)
    /// 2. Data spans multiple pages
    /// 3. Blob is truncated to a page boundary (simulating crash before last page was written)
    /// 4. Journal should recover correctly on reopen
    #[test_traced]
    fn test_fixed_journal_recover_from_page_boundary_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context: Context| async move {
            // Use a small items_per_blob to keep the test focused on a single blob
            let cfg = test_cfg(&context, NZU64!(100));
            let journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Item size is 32 bytes (Digest), page size is 44 bytes.
            // 32 doesn't divide 44, so items will cross page boundaries.
            // Physical page size = 44 + 12 (CRC) = 56 bytes.
            //
            // Write enough items to span multiple pages:
            // - 10 items = 320 logical bytes
            // - This spans ceil(320/44) = 8 logical pages
            for i in 0u64..10 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size().await, 10);
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Open the blob directly and truncate to a page boundary.
            // Physical page size = PAGE_SIZE + CHECKSUM_SIZE = 44 + 12 = 56
            let physical_page_size = PAGE_SIZE.get() as u64 + 12;
            let (blob, size) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");

            // Calculate how many full physical pages we have and truncate to lose the last one.
            let full_pages = size / physical_page_size;
            assert!(full_pages >= 2, "need at least 2 pages for this test");
            let truncate_to = (full_pages - 1) * physical_page_size;

            blob.resize(truncate_to)
                .await
                .expect("Failed to truncate blob");
            blob.sync().await.expect("Failed to sync blob");

            // Re-initialize the journal - it should recover by truncating to valid data
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal after page truncation");

            // The journal should have fewer items now (those that fit in the remaining pages).
            // With logical page size 44 and item size 32:
            // - After truncating to (full_pages-1) physical pages, we have (full_pages-1)*44 logical bytes
            // - Number of complete items = floor(logical_bytes / 32)
            let remaining_logical_bytes = (full_pages - 1) * PAGE_SIZE.get() as u64;
            let expected_items = remaining_logical_bytes / 32; // 32 = Digest::SIZE
            assert_eq!(
                journal.size().await,
                expected_items,
                "Journal should recover to {} items after truncation",
                expected_items
            );
            assert_eq!(journal.recovery_watermark().await, expected_items);

            // Verify we can still read the remaining items
            for i in 0..expected_items {
                let item = journal
                    .read(i)
                    .await
                    .expect("failed to read recovered item");
                assert_eq!(item, test_digest(i), "item {} mismatch after recovery", i);
            }

            journal.destroy().await.expect("Failed to destroy journal");
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
                inner.sections.sync_section(0).await.unwrap();
                inner.sections.sync_section(1).await.unwrap();
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
                inner.sections.sync_section(2).await.unwrap();
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

            // Empty the oldest data section in place, leaving section 1's items orphaned past the
            // gap.
            let (section0, size0) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .unwrap();
            assert!(size0 > 0, "section 0 should start durable");
            section0.resize(0).await.unwrap();
            section0.sync().await.unwrap();

            // Recovery aligns to an empty journal instead of panicking.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..0);
            assert!(matches!(
                journal.read(0).await,
                Err(Error::ItemOutOfRange(0))
            ));
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(
                names.len(),
                1,
                "orphaned newer section should be truncated away"
            );

            // The orphaned newer section is truncated away and appends resume from position 0.
            assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 0);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(42));

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest section keeps a complete item but ends with a partial item.
    ///
    /// The segmented fixed journal first trims trailing partial-item bytes to the last complete
    /// item. Contiguous recovery then treats the oldest section as a short non-tail section and
    /// truncates the newer orphaned section.
    #[test_traced]
    fn test_fixed_recovery_partial_oldest_section_orphaned_newer_section() {
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

            // Leave one complete physical page plus one trailing partial byte in the oldest
            // section. The append layer recovers the complete page, then the fixed journal trims
            // the remaining logical bytes down to one complete item.
            let (section0, size0) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .unwrap();
            let physical_page_size = PAGE_SIZE.get() as u64 + 12;
            assert!(size0 > physical_page_size);
            section0.resize(physical_page_size + 1).await.unwrap();
            section0.sync().await.unwrap();

            // Recovery trims the partial item, keeps the complete prefix, and drops section 1.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..1);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(0));
            assert!(matches!(
                journal.read(1).await,
                Err(Error::ItemOutOfRange(1))
            ));
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(
                names.len(),
                1,
                "orphaned newer section should be truncated away"
            );

            assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 1);
            assert_eq!(journal.read(1).await.unwrap(), test_digest(42));

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest section ends at a clean page boundary but is still short.
    ///
    /// No trailing bytes are repaired in this case: the first section simply contains fewer
    /// complete items than its capacity. Since a later section exists, recovery must treat the
    /// short non-tail section as the end of the contiguous prefix and drop the later section.
    #[test_traced]
    fn test_fixed_recovery_clean_short_oldest_section_orphaned_newer_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(20));

            // Build two durable sections. Section 1 is only reachable if section 0 remains a full
            // non-tail section after recovery.
            let journal = Journal::<_, u32>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..40u32 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let physical_page_size = PAGE_SIZE.get() as u64 + 12;
            let items_in_page = PAGE_SIZE.get() as u64 / u32::SIZE as u64;
            assert_eq!(PAGE_SIZE.get() as u64 % u32::SIZE as u64, 0);
            assert!(items_in_page < cfg.items_per_blob.get());

            // Truncate at a valid physical page boundary. This leaves no invalid trailing page; the
            // oldest section is simply short while section 1 still exists.
            let (section0, size0) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .unwrap();
            assert!(size0 > physical_page_size);
            section0.resize(physical_page_size).await.unwrap();
            section0.sync().await.unwrap();

            // Recovery must stop at the short non-tail section rather than skipping to section 1.
            let journal = Journal::<_, u32>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds().await, 0..items_in_page);
            assert_eq!(journal.read(items_in_page - 1).await.unwrap(), 10);
            assert!(matches!(
                journal.read(items_in_page).await,
                Err(Error::ItemOutOfRange(pos)) if pos == items_in_page
            ));
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(
                names.len(),
                1,
                "orphaned newer section should be truncated away"
            );

            // Appends resume directly after the recovered prefix.
            assert_eq!(journal.append(&42).await.unwrap(), items_in_page);
            assert_eq!(journal.read(items_in_page).await.unwrap(), 42);

            journal.destroy().await.unwrap();
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
    fn test_fixed_journal_append_after_max_size_returns_overflow() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(1));
            cfg.partition = "max-size-append-overflow".into();
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), u64::MAX)
                    .await
                    .unwrap();

            let err = journal.append(&test_digest(100)).await.unwrap_err();
            assert!(matches!(err, Error::OffsetOverflow));
            assert_eq!(journal.bounds().await, u64::MAX..u64::MAX);

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
    fn test_fixed_journal_missing_mid_section_metadata_truncates_oldest() {
        // Old meta = None (aligned), new boundary = mid-section.
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
            assert_eq!(
                journal.inner.read().await.sections.newest_section(),
                Some(2)
            );
            journal.sync().await.unwrap();

            // Simulate metadata deletion (corruption).
            let mut inner = journal.inner.write().await;
            inner.metadata.clear();
            inner.metadata.sync().await.unwrap();
            drop(inner);
            drop(journal);

            // Section 1 has items 7,8,9 but metadata is missing, so recovery falls back to the
            // section-aligned blob boundary and keeps only the contiguous prefix.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to recover journal");
            assert_eq!(journal.bounds().await, 5..8);
            assert_eq!(journal.recovery_watermark().await, 8);
            journal.destroy().await.unwrap();
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
    fn test_fixed_journal_prune_adjusts_dirty_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            for i in 0..12 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            journal.prune(5).await.unwrap();
            journal
                .commit()
                .await
                .expect("commit should not try to sync pruned dirty sections");
            assert_eq!(journal.bounds().await, 5..12);
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
    fn test_fixed_journal_clear_intent_skips_corrupt_stale_blobs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let blob_part = blob_partition(&cfg);
            let meta_cfg = MetadataConfig {
                partition: format!("{}-metadata", cfg.partition),
                codec_config: (),
            };
            let mut metadata = Metadata::<_, u64, VecU64>::init(context.child("meta"), meta_cfg)
                .await
                .unwrap();
            metadata.put(CLEAR_TARGET_KEY, 12u64.into());
            metadata.sync().await.unwrap();
            drop(metadata);

            // This name would fail `SectionsInit::open` if init tried to parse stale blobs before
            // honoring the clear intent.
            let (blob, _) = context.open(&blob_part, b"not-u64").await.unwrap();
            blob.write_at_sync(0, vec![1, 2, 3]).await.unwrap();
            drop(blob);

            let journal = Journal::<_, Digest>::init(context.child("recover"), cfg.clone())
                .await
                .expect("clear intent should discard stale corrupt blobs before section parsing");
            assert_eq!(journal.bounds().await, 12..12);
            assert_eq!(journal.recovery_watermark().await, 12);
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
    fn test_fixed_journal_clear_to_size_crash_aligned_metadata() {
        // Regression: when the old pruning boundary was section-aligned,
        // PRUNING_BOUNDARY_KEY is absent. A crash during clear_to_size after
        // blobs are recreated but before metadata sync leaves a stale
        // RECOVERY_WATERMARK_KEY with no positive conflict signal from the pruning key.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Start with an aligned state: 10 items, pruning_boundary=0.
            let journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..10u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Simulate clear_to_size(7) crash: blobs cleared, section 1 created,
            // but metadata still has recovery_watermark=10.
            let blob_part = blob_partition(&cfg);
            context.remove(&blob_part, None).await.unwrap();
            let (blob, _) = context.open(&blob_part, &1u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();

            let journal = Journal::<_, Digest>::init(context.child("crash"), cfg.clone())
                .await
                .expect("init failed after clear_to_size crash with aligned metadata");

            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 5);
            assert_eq!(bounds.end, 5);
            assert_eq!(journal.recovery_watermark().await, 5);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size_crash_aligned_metadata_far_watermark() {
        // Regression: the stale recovery watermark may point more than one section
        // past the recreated empty tail.
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

            // Simulate clear_to_size(2) crash: blobs cleared, section 0 created,
            // but metadata still has recovery_watermark=10.
            let blob_part = blob_partition(&cfg);
            context.remove(&blob_part, None).await.unwrap();
            let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();

            let journal = Journal::<_, Digest>::init(context.child("crash"), cfg.clone())
                .await
                .expect("init failed after clear_to_size crash with far aligned metadata");

            let bounds = journal.bounds().await;
            assert_eq!(bounds.start, 0);
            assert_eq!(bounds.end, 0);
            assert_eq!(journal.recovery_watermark().await, 0);
            journal.destroy().await.unwrap();
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
