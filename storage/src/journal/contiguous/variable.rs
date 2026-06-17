//! Position-based journal for variable-length items.
//!
//! The data journal is the source of truth. The offsets journal provides indexed access and records
//! the preferred recovery point for replaying data to rebuild offset entries.

use super::Reader as _;
use crate::{
    journal::{
        contiguous::{fixed, metrics::VariableMetrics as Metrics, Contiguous, Many, Mutable},
        segmented::variable::{self, decode_item, decode_length_prefix, find_item, ItemInfo},
        Error,
    },
    Context,
};
use commonware_codec::{varint::MAX_U32_VARINT_SIZE, Codec, CodecShared};
use commonware_macros::boxed;
use commonware_runtime::{
    buffer::paged::{self, CacheRef},
    Buf as _, IoBuf, IoBufMut,
};
use commonware_utils::NZUsize;
#[commonware_macros::stability(ALPHA)]
use core::ops::Range;
use futures::{future::try_join_all, stream, Stream, StreamExt as _};
use std::{
    cmp::Ordering,
    collections::BTreeMap,
    io::Cursor,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        atomic::{AtomicUsize, Ordering as AtomicOrdering},
        Arc,
    },
};
#[commonware_macros::stability(ALPHA)]
use tracing::debug;
use tracing::warn;

/// Items encoded for a deferred append, created by [`Journal::prepare_append`] and consumed by
/// [`Journal::append_prepared`].
pub struct PreparedAppend<V> {
    encoded: Vec<u8>,
    item_starts: Vec<usize>,
    _marker: PhantomData<V>,
}

const REPLAY_BUFFER_SIZE: NonZeroUsize = NZUsize!(1024);

/// Maximum positions resolved per replay batch (bounds the offsets read per step).
const REPLAY_BATCH_SIZE: u64 = 1024;

/// Suffix appended to the base partition name for the data journal.
const DATA_SUFFIX: &str = "_data";

/// Suffix appended to the base partition name for the offsets journal.
const OFFSETS_SUFFIX: &str = "_offsets";

/// Calculate the section index for a given position.
///
/// # Arguments
///
/// * `position` - The absolute position in the journal
/// * `items_per_section` - The number of items stored in each section
///
/// # Returns
///
/// The section index where the item at `position` should be stored.
///
/// # Examples
///
/// ```ignore
/// // With 10 items per section:
/// assert_eq!(position_to_section(0, 10), 0);   // position 0 -> section 0
/// assert_eq!(position_to_section(9, 10), 0);   // position 9 -> section 0
/// assert_eq!(position_to_section(10, 10), 1);  // position 10 -> section 1
/// assert_eq!(position_to_section(25, 10), 2);  // position 25 -> section 2
/// assert_eq!(position_to_section(30, 10), 3);  // position 30 -> section 3
/// ```
const fn position_to_section(position: u64, items_per_section: u64) -> u64 {
    position / items_per_section
}

/// Configuration for a [Journal].
#[derive(Clone)]
pub struct Config<C> {
    /// Base partition name. Sub-partitions will be created by appending DATA_SUFFIX and OFFSETS_SUFFIX.
    pub partition: String,

    /// The number of items to store in each section.
    ///
    /// Once set, this value cannot be changed across restarts.
    /// All non-final sections are logically full.
    pub items_per_section: NonZeroU64,

    /// Optional compression level for stored items.
    pub compression: Option<u8>,

    /// [Codec] configuration for encoding/decoding items.
    pub codec_config: C,

    /// Page cache for buffering reads from the underlying storage.
    pub page_cache: CacheRef,

    /// Write buffer size for each section.
    pub write_buffer: NonZeroUsize,
}

impl<C> Config<C> {
    /// Returns the partition name for the data journal.
    fn data_partition(&self) -> String {
        format!("{}{}", self.partition, DATA_SUFFIX)
    }

    /// Returns the partition name for the offsets journal.
    fn offsets_partition(&self) -> String {
        format!("{}{}", self.partition, OFFSETS_SUFFIX)
    }
}

/// A contiguous journal with variable-size entries.
///
/// This journal manages section assignment automatically, allowing callers to append items
/// sequentially without manually tracking section indexes.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying [Blob](commonware_runtime::Blob) will be truncated to the last valid item). Repair occurs during
/// init via the underlying segmented journals.
///
/// # Invariants
///
/// ## 1. Data Journal is Source of Truth
///
/// The data journal is always the source of truth. The offsets journal is an index
/// that may temporarily diverge during crashes. Divergences are automatically
/// aligned during init():
/// * If offsets are behind data after the recovery watermark: rebuild missing offsets by replaying
///   data from the recovery anchor.
/// * If offsets are ahead of the retained data prefix: rewind offsets to match the data-backed
///   size.
/// * If offsets.bounds().start < data.bounds().start: Prune offsets to match
///   (This can happen if we crash after pruning data journal but before pruning offsets journal)
///
/// Offsets may start after the data journal's section-aligned start when both are in the same
/// section, as in a mid-section `init_at_size`. Offsets starting in a later section imply
/// corruption because we always prune the data journal before the offsets journal.
///
/// ## 2. Offsets Recovery Watermark
///
/// The offsets journal's recovery watermark records a preferred point for replaying data to rebuild
/// offset entries after a crash. Fixed-journal recovery rejects watermarks beyond the recovered
/// offsets size as corruption. If the watermark is otherwise unusable, such as being below the
/// recovered offsets start or beyond the retained data prefix, init falls back to the offsets start.
/// Replay after the anchor stops at the first short data section and truncates newer sections so the
/// recovered journal remains a contiguous prefix.
pub struct Journal<E: Context, V: Codec> {
    /// The underlying variable-length data journal.
    data: variable::Journal<E, V>,

    /// The next position to be assigned on append (total items appended).
    ///
    /// # Invariant
    ///
    /// Always >= `pruning_boundary`. Equal when data journal is empty or fully pruned.
    size: u64,

    /// The position before which all items have been pruned.
    ///
    /// After normal operation and pruning, the value is section-aligned.
    /// After `init_at_size(N)`, the value may be mid-section.
    ///
    /// # Invariant
    ///
    /// Never decreases (pruning only moves forward).
    pruning_boundary: u64,

    /// Earliest data section modified since the last `commit()` or `sync()`.
    ///
    /// Tracks which sections need syncing. Reset by both `commit()` and `sync()` so
    /// that repeated commit-without-sync cycles only sync newly dirtied sections.
    dirty_from_section: Option<u64>,

    /// Index mapping positions to byte offsets within the data journal.
    /// The section can be calculated from the position using items_per_section.
    offsets: fixed::Journal<E, u64>,

    /// The number of items per section.
    ///
    /// # Invariant
    ///
    /// This value is immutable after initialization and must remain consistent
    /// across restarts. Changing this value will result in data loss or corruption.
    items_per_section: u64,

    /// Optional compression level when encoding items.
    compression: Option<u8>,

    /// [Codec] configuration for decoding items.
    codec_config: V::Cfg,

    /// Journal and Reader metrics.
    metrics: Arc<Metrics<E>>,

    /// Number of live [Reader]s. Gates rewind, which would truncate bytes a reader can see.
    readers: Arc<AtomicUsize>,
}

/// Counts a live reader in the journal's reader count until dropped.
struct ReadersGuard(Arc<AtomicUsize>);

impl Drop for ReadersGuard {
    fn drop(&mut self) {
        self.0.fetch_sub(1, AtomicOrdering::Release);
    }
}

/// A reader over a snapshot of the variable journal.
pub struct Reader<E: Context, V: Codec> {
    /// Journal bounds at snapshot time.
    bounds: std::ops::Range<u64>,

    /// Owned read handles for each retained data section at snapshot time.
    sections: Arc<BTreeMap<u64, paged::Reader<E::Blob>>>,

    /// Maps positions to byte offsets within the data sections.
    offsets: fixed::Reader<E, u64>,

    /// The number of items in each section.
    items_per_section: u64,

    /// [Codec] configuration for decoding items.
    codec_config: V::Cfg,

    /// Whether items are zstd-compressed.
    compressed: bool,

    /// Journal and Reader metrics.
    metrics: Arc<Metrics<E>>,

    /// Decrements the journal's reader count on drop.
    _guard: ReadersGuard,
}

impl<E: Context, V: CodecShared> Reader<E, V> {
    /// Validate that `position` is readable within the snapshot's bounds.
    const fn validate_readable(&self, position: u64) -> Result<(), Error> {
        if position >= self.bounds.end {
            return Err(Error::ItemOutOfRange(position));
        }
        if position < self.bounds.start {
            return Err(Error::ItemPruned(position));
        }
        Ok(())
    }

    /// Return the read handle for `section`.
    ///
    /// The snapshot's sections contiguously cover its bounds, so every section containing an
    /// in-bounds position is present.
    fn section_handle(&self, section: u64) -> &paged::Reader<E::Blob> {
        self.sections
            .get(&section)
            .expect("section within bounds must be in snapshot")
    }

    /// Read the varint-framed item at byte `offset` via `handle`.
    async fn read_at_offset(
        &self,
        handle: &paged::Reader<E::Blob>,
        offset: u64,
    ) -> Result<V, Error> {
        // Read the varint header (max 5 bytes for u32).
        let (buf, available) = handle
            .read_up_to(
                offset,
                MAX_U32_VARINT_SIZE,
                IoBufMut::with_capacity(MAX_U32_VARINT_SIZE),
            )
            .await
            .map_err(Error::Runtime)?;
        let buf = buf.freeze();
        let mut cursor = Cursor::new(buf.slice(..available));
        let (_, item_info) = find_item(&mut cursor, offset)?;

        // Decode the item, either directly from the buffer or by chaining the prefix with the
        // remainder.
        match item_info {
            ItemInfo::Complete {
                varint_len,
                data_len,
            } => decode_item::<V>(
                buf.slice(varint_len..varint_len + data_len),
                &self.codec_config,
                self.compressed,
            ),
            ItemInfo::Incomplete {
                varint_len,
                prefix_len,
                total_len,
            } => {
                let prefix = buf.slice(varint_len..varint_len + prefix_len);
                let read_offset = offset + varint_len as u64 + prefix_len as u64;
                let remainder = handle
                    .read_at(read_offset, total_len - prefix_len)
                    .await
                    .map_err(Error::Runtime)?;
                decode_item::<V>(prefix.chain(remainder), &self.codec_config, self.compressed)
            }
        }
    }

    /// Read consecutive items in one section. `offsets` must be strictly increasing byte offsets
    /// of byte-adjacent items.
    ///
    /// Returns [Error::OffsetDataMismatch] if the on-disk varint at any offset reports a size
    /// inconsistent with the gap to the next offset.
    async fn read_consecutive(
        &self,
        handle: &paged::Reader<E::Blob>,
        section: u64,
        offsets: &[u64],
    ) -> Result<Vec<V>, Error> {
        // Trivial spans take the single-item path directly.
        if offsets.len() <= 1 {
            let mut items = Vec::with_capacity(offsets.len());
            for &offset in offsets {
                items.push(self.read_at_offset(handle, offset).await?);
            }
            return Ok(items);
        }

        // Read the byte span covering every item but the last in one operation; the last item's
        // length is unknown, so it goes through the single-item path. Corrupt offsets data may
        // not be strictly increasing, so the span is computed checked.
        let start = offsets[0];
        let end = offsets[offsets.len() - 1];
        let range_len = end
            .checked_sub(start)
            .and_then(|len| usize::try_from(len).ok())
            .ok_or(Error::OffsetOverflow)?;
        let bytes = handle
            .read_at(start, range_len)
            .await
            .map_err(Error::Runtime)?
            .coalesce();
        let bytes = bytes.as_ref();

        let mut items = Vec::with_capacity(offsets.len());
        let mut local_offset = 0usize;
        for window in offsets.windows(2) {
            let offset = window[0];
            let next_offset = window[1];
            // Corrupt offsets data may not be strictly increasing.
            let item_len = next_offset
                .checked_sub(offset)
                .and_then(|len| usize::try_from(len).ok())
                .ok_or(Error::OffsetOverflow)?;

            let mut cursor = Cursor::new(&bytes[local_offset..]);
            let (size, varint_len) = decode_length_prefix(&mut cursor)?;
            let actual_len = size + varint_len;
            if actual_len != item_len {
                return Err(Error::OffsetDataMismatch {
                    section,
                    offset,
                    expected_len: item_len,
                    actual_len,
                });
            }

            let data_start = local_offset
                .checked_add(varint_len)
                .ok_or(Error::OffsetOverflow)?;
            let data_end = local_offset
                .checked_add(item_len)
                .ok_or(Error::OffsetOverflow)?;
            // data_end should never exceed the read span, but guard the slice defensively.
            if data_end > bytes.len() {
                return Err(Error::OffsetDataMismatch {
                    section,
                    offset,
                    expected_len: item_len,
                    actual_len,
                });
            }

            items.push(decode_item::<V>(
                &bytes[data_start..data_end],
                &self.codec_config,
                self.compressed,
            )?);

            local_offset = data_end;
        }

        items.push(self.read_at_offset(handle, end).await?);
        Ok(items)
    }

    /// Read an item synchronously from cached bytes, returning `None` on any miss.
    fn try_read_sync_into(&self, position: u64, buf: &mut Vec<u8>) -> Option<V> {
        self.validate_readable(position).ok()?;
        let offset = self.offsets.try_read_sync(position)?;
        let handle = self
            .sections
            .get(&position_to_section(position, self.items_per_section))?;
        let remaining = handle.try_size()?.checked_sub(offset)?;
        let header_len = usize::try_from(remaining.min(MAX_U32_VARINT_SIZE as u64)).ok()?;
        if header_len == 0 {
            return None;
        }

        // Read the varint header to determine item size.
        let mut header = [0u8; MAX_U32_VARINT_SIZE];
        if !handle.try_read_sync(offset, &mut header[..header_len]) {
            return None;
        }
        let mut cursor = Cursor::new(&header[..header_len]);
        let (_, item_info) = find_item(&mut cursor, offset).ok()?;

        let (varint_len, data_len) = match item_info {
            ItemInfo::Complete {
                varint_len,
                data_len,
            } => (varint_len, data_len),
            ItemInfo::Incomplete {
                varint_len,
                total_len,
                ..
            } => (varint_len, total_len),
        };
        let item_len = varint_len.checked_add(data_len)?;
        if item_len > usize::try_from(remaining).ok()? {
            return None;
        }

        // If the full item fits in the header read, decode directly.
        if item_len <= header_len {
            return decode_item::<V>(
                &header[varint_len..varint_len + data_len],
                &self.codec_config,
                self.compressed,
            )
            .ok();
        }

        // Otherwise try reading the full item from cache.
        buf.resize(item_len, 0);
        if !handle.try_read_sync(offset, buf) {
            return None;
        }
        decode_item::<V>(
            &buf[varint_len..varint_len + data_len],
            &self.codec_config,
            self.compressed,
        )
        .ok()
    }

    /// Read one replay batch starting at `start`: as many consecutive items from `start`'s
    /// section as fit in `buffer` bytes (always at least one). Returns the items with their
    /// positions and the next position to replay.
    async fn replay_batch(&self, start: u64, buffer: usize) -> Result<(Vec<(u64, V)>, u64), Error> {
        // Bound the batch to `start`'s section (consecutive positions are only byte-adjacent
        // within one section) and to a fixed position count (bounds offsets-read memory).
        let section = position_to_section(start, self.items_per_section);
        let remaining_in_section = self.items_per_section - (start % self.items_per_section);
        let window_end = start
            .saturating_add(remaining_in_section.min(REPLAY_BATCH_SIZE))
            .min(self.bounds.end);
        let positions: Vec<u64> = (start..window_end).collect();
        let offsets = self
            .offsets
            .read_many(&positions)
            .await
            .map_err(|e| match e {
                Error::ItemOutOfRange(e) | Error::ItemPruned(e) => {
                    Error::Corruption(format!("section/item should be found, but got: {e}"))
                }
                other => other,
            })?;

        // Extend the run while its byte span fits the buffer (a single item of any size is
        // always read; the per-item path handles items larger than the buffer).
        let mut run_len = 1;
        while run_len < offsets.len()
            && offsets[run_len]
                .checked_sub(offsets[0])
                .is_some_and(|span| span <= buffer as u64)
        {
            run_len += 1;
        }

        let handle = self.section_handle(section);
        let items = self
            .read_consecutive(handle, section, &offsets[..run_len])
            .await?;
        let batch = positions[..run_len].iter().copied().zip(items).collect();
        Ok((batch, start + run_len as u64))
    }
}

impl<E: Context, V: CodecShared> super::Reader for Reader<E, V> {
    type Item = V;

    fn bounds(&self) -> std::ops::Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<V, Error> {
        self.metrics.read_calls.inc();

        // Serve from the page cache synchronously when possible, collapsing the offsets and data
        // lookups into buffer copies and avoiding the async storage path on a hit.
        let mut buf = Vec::new();
        if let Some(item) = self.try_read_sync_into(position, &mut buf) {
            self.metrics.items_read.inc();
            return Ok(item);
        }

        let _timer = self.metrics.read_timer();
        self.validate_readable(position)?;
        let offset = self.offsets.read(position).await?;
        let handle = self.section_handle(position_to_section(position, self.items_per_section));
        let item = self.read_at_offset(handle, offset).await?;
        self.metrics.items_read.inc();
        Ok(item)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<V>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let _timer = self.metrics.read_many_timer();
        self.metrics.read_many_calls.inc();
        if positions[0] < self.bounds.start {
            return Err(Error::ItemPruned(positions[0]));
        }
        let last_position = *positions.last().expect("positions is not empty");
        if last_position >= self.bounds.end {
            return Err(Error::ItemOutOfRange(last_position));
        }

        // Read the items from cache if possible.
        let mut result: Vec<Option<V>> = Vec::with_capacity(positions.len());
        let mut miss_indices = Vec::with_capacity(positions.len());
        let mut miss_positions = Vec::with_capacity(positions.len());
        let mut buf = Vec::new();
        let mut prev: Option<u64> = None;
        for (i, &position) in positions.iter().enumerate() {
            if prev.is_some_and(|p| position <= p) {
                return Err(Error::PositionsNotIncreasing);
            }
            prev = Some(position);
            if let Some(item) = self.try_read_sync_into(position, &mut buf) {
                result.push(Some(item));
            } else {
                result.push(None);
                miss_indices.push(i);
                miss_positions.push(position);
            }
        }

        if miss_positions.is_empty() {
            self.metrics.items_read.inc_by(positions.len() as u64);
            return Ok(result.into_iter().map(|r| r.unwrap()).collect());
        }

        // Read the offsets of all items that were not found in the cache.
        let miss_offsets = self
            .offsets
            .read_many(&miss_positions)
            .await
            .map_err(|e| match e {
                Error::ItemOutOfRange(e) | Error::ItemPruned(e) => {
                    Error::Corruption(format!("section/item should be found, but got: {e}"))
                }
                other => other,
            })?;

        // Group runs of consecutive positions that fall into the same section and perform a
        // consecutive read for each run.
        let mut group_start = 0;
        while group_start < miss_positions.len() {
            let section = position_to_section(miss_positions[group_start], self.items_per_section);
            let mut group_end = group_start + 1;
            while group_end < miss_positions.len()
                && position_to_section(miss_positions[group_end], self.items_per_section) == section
            {
                group_end += 1;
            }

            let handle = self.section_handle(section);
            let mut run_start = group_start;
            while run_start < group_end {
                let mut run_end = run_start + 1;
                while run_end < group_end
                    && miss_positions[run_end - 1].checked_add(1) == Some(miss_positions[run_end])
                {
                    run_end += 1;
                }

                let items = self
                    .read_consecutive(handle, section, &miss_offsets[run_start..run_end])
                    .await?;

                for (item, &miss_idx) in items.into_iter().zip(&miss_indices[run_start..run_end]) {
                    result[miss_idx] = Some(item);
                }
                run_start = run_end;
            }
            group_start = group_end;
        }

        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result.into_iter().map(|r| r.unwrap()).collect())
    }

    fn try_read_sync(&self, position: u64) -> Option<V> {
        let mut buf = Vec::new();
        let item = self.try_read_sync_into(position, &mut buf)?;
        self.metrics.try_read_sync_hits.inc();
        self.metrics.items_read.inc();
        Some(item)
    }

    async fn replay(
        &self,
        buffer_size: NonZeroUsize,
        start_pos: u64,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + Send, Error> {
        // Validate bounds.
        if start_pos < self.bounds.start {
            return Err(Error::ItemPruned(start_pos));
        }
        if start_pos > self.bounds.end {
            return Err(Error::ItemOutOfRange(start_pos));
        }

        // Stream items in batches. The unfold state is the next position to emit; an error
        // pins it to `bounds.end`, terminating the stream.
        let stream = stream::unfold(start_pos, move |next_pos| async move {
            if next_pos >= self.bounds.end {
                return None;
            }
            match self.replay_batch(next_pos, buffer_size.get()).await {
                Ok((batch, next)) => Some((batch.into_iter().map(Ok).collect::<Vec<_>>(), next)),
                Err(err) => Some((vec![Err(err)], self.bounds.end)),
            }
        })
        .flat_map(stream::iter);

        Ok(stream)
    }
}

impl<E: Context, V: CodecShared> Journal<E, V> {
    #[inline]
    fn mark_dirty_from(&mut self, section: u64) {
        self.dirty_from_section = Some(
            self.dirty_from_section
                .map_or(section, |existing| existing.min(section)),
        );
    }

    /// Sync data sections backing rebuilt offsets before the offsets are made durable.
    async fn sync_data_range(
        data: &variable::Journal<E, V>,
        start_position: u64,
        end_position: u64,
        items_per_section: u64,
    ) -> Result<(), Error> {
        if start_position >= end_position {
            return Ok(());
        }

        let start_section = position_to_section(start_position, items_per_section);
        let end_section = position_to_section(end_position - 1, items_per_section);
        let start_section = data
            .oldest_section()
            .map_or(start_section, |oldest| start_section.max(oldest));
        try_join_all((start_section..=end_section).map(|section| data.sync(section))).await?;
        Ok(())
    }

    /// Initialize a contiguous variable journal.
    ///
    /// # Crash Recovery
    ///
    /// The data journal is the source of truth. If the offsets journal is inconsistent
    /// it will be updated to match the data journal.
    #[boxed]
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let items_per_section = cfg.items_per_section.get();
        let data_partition = cfg.data_partition();
        let offsets_partition = cfg.offsets_partition();

        // Initialize underlying variable data journal
        let mut data = variable::Journal::init(
            context.child("data"),
            variable::Config {
                partition: data_partition,
                compression: cfg.compression,
                codec_config: cfg.codec_config.clone(),
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // If a prior `init_at_size`/`clear_to_size` crashed mid-reset, the offsets journal carries
        // a staged clear. `init_cleared` discards data before finishing that reset so the two sides
        // are reconciled and stale data is never replayed past the reset size.
        let mut offsets = fixed::Journal::<E, u64>::init_cleared(
            context.child("offsets"),
            fixed::Config {
                partition: offsets_partition,
                items_per_blob: cfg.items_per_section,
                page_cache: cfg.page_cache,
                write_buffer: cfg.write_buffer,
            },
            || data.clear(),
        )
        .await?;

        // Validate and align offsets journal to match data journal
        let (pruning_boundary, size) =
            Self::align_journals(&mut data, &mut offsets, items_per_section).await?;

        let metrics = Metrics::new(context);
        metrics.update(size, pruning_boundary, items_per_section);

        Ok(Self {
            data,
            size,
            pruning_boundary,
            dirty_from_section: None,
            offsets,
            items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            metrics: Arc::new(metrics),
            readers: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Initialize an empty [Journal] at the given logical `size`.
    ///
    /// This discards any existing data and offsets. The offsets reset intent is staged before the
    /// data journal is cleared so recovery can complete the requested reset if a crash interrupts
    /// the operation.
    ///
    /// Returns a journal with journal.bounds() == Range{start: size, end: size}
    /// and next append at position `size`.
    #[commonware_macros::stability(ALPHA)]
    pub async fn init_at_size(context: E, cfg: Config<V::Cfg>, size: u64) -> Result<Self, Error> {
        let mut data = variable::Journal::init(
            context.child("data"),
            variable::Config {
                partition: cfg.data_partition(),
                compression: cfg.compression,
                codec_config: cfg.codec_config.clone(),
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        // `init_at_size_cleared` durably stages the offsets reset, clears data, then completes the
        // reset. A crash at any point leaves a staged clear that the next `init` (via
        // `init_cleared`) finishes, so stale data can never outlive the reset.
        let offsets = fixed::Journal::<E, u64>::init_at_size_cleared(
            context.child("offsets"),
            fixed::Config {
                partition: cfg.offsets_partition(),
                items_per_blob: cfg.items_per_section,
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            },
            size,
            || data.clear(),
        )
        .await?;

        let items_per_section = cfg.items_per_section.get();
        let metrics = Metrics::new(context);
        metrics.update(size, size, items_per_section);

        Ok(Self {
            data,
            size,
            pruning_boundary: size,
            dirty_from_section: None,
            offsets,
            items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            metrics: Arc::new(metrics),
            readers: Arc::new(AtomicUsize::new(0)),
        })
    }

    /// Initialize a [Journal] for use in state sync.
    ///
    /// The bounds are item locations (not section indexes). This function prepares the
    /// on-disk journal so that subsequent appends go to the correct physical location for the
    /// requested range.
    ///
    /// Behavior by existing on-disk state:
    /// - Fresh (no data): returns an empty journal, resetting to `range.start` if needed.
    /// - Stale (all data strictly before `range.start`): resets to `range.start` using the
    ///   crash-safe clear path and returns an empty journal.
    /// - Overlap within [`range.start`, `range.end`]:
    ///   - Prunes toward `range.start` (section-aligned, so some items before
    ///     `range.start` may be retained)
    /// - Data beyond `range.end`: returns [Error::ItemOutOfRange].
    ///
    /// # Arguments
    /// - `context`: storage context
    /// - `cfg`: journal configuration
    /// - `range`: range of item locations to retain
    ///
    /// # Returns
    /// A contiguous journal ready for sync operations. The journal's size will be within the range.
    ///
    /// # Errors
    /// Returns [Error::ItemOutOfRange] if existing data extends beyond `range.end`.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn init_sync(
        context: E,
        cfg: Config<V::Cfg>,
        range: Range<u64>,
    ) -> Result<Self, Error> {
        assert!(!range.is_empty(), "range must not be empty");

        debug!(
            range.start,
            range.end,
            items_per_section = cfg.items_per_section.get(),
            "initializing contiguous variable journal for sync"
        );

        // Initialize contiguous journal
        let mut journal = Self::init(context.child("journal"), cfg.clone()).await?;

        let size = journal.size();

        // No existing data - reset to sync range start if needed
        if size == 0 {
            if range.start == 0 {
                debug!("no existing journal data, returning empty journal");
                return Ok(journal);
            } else {
                debug!(
                    range.start,
                    "no existing journal data, resetting to sync range start"
                );
                journal.clear_to_size(range.start).await?;
                return Ok(journal);
            }
        }

        // After a same-section crash during a previous clear_to_size, the journal may recover to a
        // stale position ahead of the requested start.
        let bounds = journal.reader().bounds();
        if bounds.is_empty() && bounds.start > range.start {
            journal.clear_to_size(range.start).await?;
            return Ok(journal);
        }

        // Check if data exceeds the sync range
        if size > range.end {
            return Err(Error::ItemOutOfRange(size));
        }

        // If all existing data is before our sync range, reset to range start
        if size <= range.start {
            debug!(
                size,
                range.start, "existing journal data is stale, resetting to start position"
            );
            journal.clear_to_size(range.start).await?;
            return Ok(journal);
        }

        // Prune to lower bound if needed
        if !bounds.is_empty() && bounds.start < range.start {
            debug!(
                oldest_pos = bounds.start,
                range.start, "pruning journal to sync range start"
            );
            journal.prune(range.start).await?;
        }

        Ok(journal)
    }

    /// Rewind the journal to the given size, discarding items from the end.
    ///
    /// After rewinding to size N, the journal will contain exactly N items, and the next append
    /// will receive position N.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if `size` is larger than current size.
    /// Returns [Error::ItemPruned] if `size` is smaller than the pruning boundary.
    ///
    /// # Warning
    ///
    /// - This operation is not guaranteed to survive restarts until `commit` or `sync` is called.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        // Validate rewind target
        match size.cmp(&self.size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()), // No-op
            std::cmp::Ordering::Less => {}
        }

        // Rewind never updates the pruning boundary.
        if size < self.pruning_boundary {
            return Err(Error::ItemPruned(size));
        }

        // A rewind truncates bytes a live reader can still see, so it is refused while any
        // reader is outstanding.
        if self.readers.load(AtomicOrdering::Acquire) != 0 {
            return Err(Error::BlobInUse(position_to_section(
                size,
                self.items_per_section,
            )));
        }

        // Read the offset of the first item to discard (at position 'size').
        let discard_offset = self.offsets.reader().read(size).await?;
        let discard_section = position_to_section(size, self.items_per_section);

        self.data
            .rewind_to_offset(discard_section, discard_offset)
            .await?;
        self.offsets.rewind(size).await?;

        // Update our size
        self.size = size;
        self.mark_dirty_from(discard_section);
        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_section);

        Ok(())
    }

    /// Append a new item to the journal, returning its position.
    ///
    /// The position returned is a stable, consecutively increasing value starting from 0.
    /// This position remains constant after pruning.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails or if the item cannot
    /// be encoded.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger alignment in [Journal::init].
    pub async fn append(&mut self, item: &V) -> Result<u64, Error> {
        let _timer = self.metrics.append_timer();
        self.metrics.append_calls.inc();
        self.append_many_inner(Many::Flat(std::slice::from_ref(item)))
            .await
    }

    /// Append items to the journal, returning the position of the last item appended.
    ///
    /// Returns [Error::EmptyAppend] if items is empty.
    pub async fn append_many<'a>(&'a mut self, items: Many<'a, V>) -> Result<u64, Error> {
        let _timer = self.metrics.append_many_timer();
        self.metrics.append_many_calls.inc();
        self.append_many_inner(items).await
    }

    async fn append_many_inner<'a>(&'a mut self, items: Many<'a, V>) -> Result<u64, Error> {
        self.write_encoded(self.prepare_append(items)?).await
    }

    /// Encode `items` into a buffer that can be appended later with [`Self::append_prepared`].
    ///
    /// This lets callers serialize borrowed items synchronously, release those borrows, and
    /// perform the append without holding unrelated locks across journal I/O.
    pub fn prepare_append(&self, items: Many<'_, V>) -> Result<PreparedAppend<V>, Error> {
        let mut encoded = Vec::new();
        let mut item_starts = Vec::with_capacity(items.len());
        let mut encode = |item: &V| {
            item_starts.push(encoded.len());
            variable::Journal::<E, V>::encode_item_into(self.compression, item, &mut encoded)
        };
        match items {
            Many::Flat(items) => {
                for item in items {
                    encode(item)?;
                }
            }
            Many::Nested(nested_items) => {
                for items in nested_items {
                    for item in *items {
                        encode(item)?;
                    }
                }
            }
        }
        Ok(PreparedAppend {
            encoded,
            item_starts,
            _marker: PhantomData,
        })
    }

    /// Append items encoded by [`Self::prepare_append`], returning the position of the last item
    /// appended.
    ///
    /// Returns [Error::EmptyAppend] if `prepared` contains no items.
    pub async fn append_prepared(&mut self, prepared: PreparedAppend<V>) -> Result<u64, Error> {
        let _timer = self.metrics.append_prepared_timer();
        self.metrics.append_prepared_calls.inc();
        self.write_encoded(prepared).await
    }

    // Write pre-encoded items; shared by all append paths. Records no call metrics.
    async fn write_encoded(&mut self, prepared: PreparedAppend<V>) -> Result<u64, Error> {
        let PreparedAppend {
            encoded,
            item_starts,
            ..
        } = prepared;
        let items_count = item_starts.len();
        if items_count == 0 {
            return Err(Error::EmptyAppend);
        }
        let encoded = IoBuf::from(encoded);

        // Reject the append before writing anything (to either the data or offsets journal) if
        // it would push the size past `u64::MAX`.
        self.size
            .checked_add(items_count as u64)
            .ok_or(Error::SizeOverflow)?;

        let mut written = 0;
        while written < items_count {
            let section = position_to_section(self.size, self.items_per_section);
            let pos_in_section = self.size % self.items_per_section;
            let remaining_space = (self.items_per_section - pos_in_section) as usize;
            let batch_count = remaining_space.min(items_count - written);
            let batch_start = item_starts[written];
            let batch_end = item_starts
                .get(written + batch_count)
                .copied()
                .unwrap_or(encoded.len());

            // Append pre-encoded data to the data journal, then convert relative item starts
            // into absolute offsets.
            let base_offset = self
                .data
                .append_raw(section, encoded.slice(batch_start..batch_end))
                .await?;

            let absolute_offsets = item_starts[written..written + batch_count]
                .iter()
                .map(|&start| {
                    base_offset
                        .checked_add((start - batch_start) as u64)
                        .ok_or(Error::OffsetOverflow)
                })
                .collect::<Result<Vec<u64>, _>>()?;

            // Append the offsets for this section batch to the offsets journal.
            let last_offsets_pos = self
                .offsets
                .append_many(Many::Flat(&absolute_offsets))
                .await?;
            assert_eq!(last_offsets_pos, self.size + batch_count as u64 - 1);

            self.size += batch_count as u64;
            written += batch_count;
            self.mark_dirty_from(section);
        }

        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_section);
        Ok(self.size - 1)
    }

    /// Acquire a reader that holds an owned, consistent snapshot of the journal.
    pub fn reader(&self) -> Reader<E, V> {
        self.readers.fetch_add(1, AtomicOrdering::Relaxed);
        Reader {
            bounds: self.pruning_boundary..self.size,
            sections: self.data.section_readers(),
            offsets: self.offsets.reader(),
            items_per_section: self.items_per_section,
            codec_config: self.codec_config.clone(),
            compressed: self.compression.is_some(),
            metrics: self.metrics.clone(),
            _guard: ReadersGuard(self.readers.clone()),
        }
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub const fn size(&self) -> u64 {
        self.size
    }

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    ///
    /// Errors may leave the journal in an inconsistent state. The journal should be closed and
    /// reopened to trigger alignment in [Journal::init].
    pub async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        if min_position <= self.pruning_boundary {
            return Ok(false);
        }

        // Cap min_position to size to maintain the invariant pruning_boundary <= size
        let min_position = min_position.min(self.size);

        // Calculate section index
        let min_section = position_to_section(min_position, self.items_per_section);

        let pruned = self.data.prune(min_section).await?;
        if pruned {
            let new_oldest = (min_section * self.items_per_section).max(self.pruning_boundary);
            self.pruning_boundary = new_oldest;
            self.offsets.prune(new_oldest).await?;
            if let Some(dirty_from) = self.dirty_from_section {
                self.dirty_from_section = Some(dirty_from.max(min_section));
            }
            self.metrics
                .update(self.size, self.pruning_boundary, self.items_per_section);
        }
        Ok(pruned)
    }

    /// Flush dirty data sections to storage.
    ///
    /// Sections are synced concurrently. Ordering is not required for recovery: appends only add
    /// data, so committed sections are never at risk, and recovery replays the data journal as the
    /// source of truth and truncates at the first short or missing section, so a crash that leaves a
    /// gap still recovers a contiguous prefix no shorter than the last completed commit.
    async fn flush_dirty_data(&self) -> Result<(), Error> {
        if let Some(start_section) = self.dirty_from_section {
            let tail_section = position_to_section(self.size, self.items_per_section);
            let start_section = self
                .data
                .oldest_section()
                .map(|oldest| start_section.max(oldest))
                // With no retained data blobs, any earlier dirty section was cleared or pruned.
                // Syncing the tail section is harmless when it does not exist.
                .unwrap_or(tail_section);
            try_join_all((start_section..=tail_section).map(|section| self.data.sync(section)))
                .await?;
        }
        Ok(())
    }

    /// Persist dirty data sections so committed data survives a crash.
    ///
    /// Does not advance the recovery watermark, so reopen may need to replay entries beyond
    /// the previous `sync()`.
    pub async fn commit(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.commit_timer();
        self.metrics.record_commit();
        self.flush_dirty_data().await?;
        self.dirty_from_section = None;
        Ok(())
    }

    /// Persist dirty data sections and all metadata for both the data and offsets journals.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        self.flush_dirty_data().await?;
        self.offsets.sync().await?;
        self.dirty_from_section = None;
        Ok(())
    }

    /// Remove any underlying blobs created by the journal.
    ///
    /// This destroys both the data journal and the offsets journal.
    ///
    /// # Crash Safety
    ///
    /// This operation is intended for final teardown and is not crash-safe. If interrupted,
    /// reopening the same partitions may observe partially removed state. Use [Self::init_at_size]
    /// for a recoverable reset.
    pub async fn destroy(self) -> Result<(), Error> {
        self.data.destroy().await?;
        self.offsets.destroy().await
    }

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    /// After clearing, the journal will behave as if initialized with `init_at_size(new_size)`.
    /// The offsets reset intent is staged before the data journal is cleared so recovery can
    /// complete the requested reset if a crash interrupts the operation.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn clear_to_size(&mut self, new_size: u64) -> Result<(), Error> {
        // Stage in offsets first so a crash mid-clear leaves an intent that recovery completes.
        // `clear_to_size` re-stages the same target idempotently before completing.
        self.offsets.stage_clear_intent(new_size).await?;
        self.data.clear().await?;
        self.offsets.clear_to_size(new_size).await?;
        self.size = new_size;
        self.pruning_boundary = new_size;
        self.dirty_from_section = None;
        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_section);
        Ok(())
    }

    /// Align the offsets journal and data journal to be consistent in case a crash occurred
    /// on a previous run and left the journals in an inconsistent state.
    ///
    /// The data journal is the source of truth. This function replays the data journal as needed to
    /// verify or rebuild the offsets suffix, then fixes any mismatches.
    ///
    /// # Returns
    ///
    /// Returns `(pruning_boundary, size)` for the contiguous journal.
    async fn align_journals(
        data: &mut variable::Journal<E, V>,
        offsets: &mut fixed::Journal<E, u64>,
        items_per_section: u64,
    ) -> Result<(u64, u64), Error> {
        // === Handle empty data journal case ===
        // Count the newest data section, removing any empty trailing sections
        // left by a crash before append buffers became durable.
        let items_in_last_section = loop {
            let Some(last_section) = data.newest_section() else {
                break 0;
            };

            let items_in_last_section = {
                let stream = data.replay(last_section, 0, REPLAY_BUFFER_SIZE).await?;
                futures::pin_mut!(stream);
                let mut count = 0u64;
                while let Some(result) = stream.next().await {
                    result?; // Propagate replay errors (corruption, etc.)
                    count += 1;
                }
                count
            };

            if items_in_last_section > items_per_section {
                return Err(Error::Corruption(format!(
                    "data section has too many items: expected at most {items_per_section}, got {items_in_last_section}"
                )));
            }

            // Stop once we find replayable data or only one empty section
            // remains for the existing empty-data repair path.
            if items_in_last_section > 0 || data.num_sections() == 1 {
                break items_in_last_section;
            }

            let previous_section = last_section
                .checked_sub(1)
                .expect("num_sections >= 2 implies newest_section >= 1");
            let previous_size = data.size(previous_section).await?;
            warn!(
                section = last_section,
                "crash repair: removing empty trailing data section"
            );
            data.rewind(previous_section, previous_size).await?;
        };

        // After trimming empty trailing sections, a zero item count means the data journal is
        // empty: either no sections remain, or one empty section remains for repair below.
        if items_in_last_section == 0 {
            let offsets_bounds = {
                let offsets_reader = offsets.reader();
                offsets_reader.bounds()
            };
            let size = offsets_bounds.end;

            if !data.is_empty() {
                // A section exists but contains 0 items. This can happen in two cases:
                // 1. Rewind crash: we rewound the data journal but crashed before rewinding offsets
                // 2. First append crash: we opened the first section blob but crashed before writing to it
                // In both cases, calculate target position from the first remaining section
                // SAFETY: data is non-empty (checked above)
                let data_first_section = data.oldest_section().unwrap();
                let data_section_start = data_first_section * items_per_section;
                let target_pos = data_section_start.max(offsets_bounds.start);

                warn!("crash repair: clearing offsets to {target_pos} (empty section crash)");
                offsets.clear_to_size(target_pos).await?;
                return Ok((target_pos, target_pos));
            }

            // data.blobs is empty. This can happen in two cases:
            // 1. We completely pruned the data journal but crashed before pruning
            //    the offsets journal.
            // 2. The data journal was never opened.
            if !offsets_bounds.is_empty() {
                // Offsets has unpruned entries but data is gone - clear to match empty state.
                // We use clear_to_size (not prune) to ensure bounds.start == bounds.end,
                // even when size is mid-section.
                warn!("crash repair: clearing offsets to {size} (prune-all crash)");
                offsets.clear_to_size(size).await?;
            }

            return Ok((size, size));
        }

        // === Handle non-empty data journal case ===
        let data_first_section = data.oldest_section().unwrap();
        let data_oldest_pos = data_first_section * items_per_section;

        // Align pruning state at the section level. After alignment,
        // position_to_section(offsets_bounds.start) == data_first_section.
        // Mid-section offsets start (from init_at_size) is valid within the same section.
        {
            let offsets_bounds = {
                let offsets_reader = offsets.reader();
                offsets_reader.bounds()
            };

            // Offsets journal ending before the oldest retained data section represents an
            // impossible state under normal crash/prune sequences, indicating external corruption.
            if offsets_bounds.end < data_oldest_pos {
                return Err(Error::Corruption(format!(
                    "offsets journal size {} is behind data oldest position {}",
                    offsets_bounds.end, data_oldest_pos
                )));
            }
            let offsets_start_section = offsets_bounds.start / items_per_section;
            match offsets_start_section.cmp(&data_first_section) {
                Ordering::Less => {
                    warn!("crash repair: pruning offsets journal to {data_oldest_pos}");
                    offsets.prune(data_oldest_pos).await?;
                }
                Ordering::Equal => {}
                Ordering::Greater => {
                    // Prune always removes data before offsets, so offsets should never be
                    // ahead by a section.
                    return Err(Error::Corruption(format!(
                        "offsets start section {offsets_start_section} ahead of \
                         data start section {data_first_section}"
                    )));
                }
            }
        }

        // Re-fetch bounds since prune may have been called above.
        let offsets_bounds = {
            let offsets_reader = offsets.reader();
            offsets_reader.bounds()
        };
        // The newest data section bounds how far recovery can possibly go. If it is also the
        // oldest retained section, its logical start may be a mid-section pruning boundary.
        let data_newest_section = data
            .newest_section()
            .expect("non-empty data journal should have newest section");
        let data_newest_start = data_newest_section
            .checked_mul(items_per_section)
            .ok_or(Error::OffsetOverflow)?;
        let retained_data_end_bound = data_newest_start
            .max(offsets_bounds.start)
            .checked_add(items_in_last_section)
            .ok_or(Error::OffsetOverflow)?;

        let recovery_watermark = offsets.recovery_watermark();

        if recovery_watermark > offsets_bounds.end {
            // This condition should be unreachable (fixed-journal init rejects watermark > size),
            // so if it were reachable it would indicate external corruption.
            return Err(Error::Corruption(format!(
                "offsets recovery watermark {recovery_watermark} exceeds offsets size {}",
                offsets_bounds.end
            )));
        }
        let recovery_start = if recovery_watermark < offsets_bounds.start
            || recovery_watermark > retained_data_end_bound
        {
            warn!(
                recovery_watermark,
                start = offsets_bounds.start,
                end = offsets_bounds.end,
                retained_data_end_bound,
                "crash repair: offsets recovery watermark is unusable, rebuilding from offsets start"
            );
            offsets_bounds.start
        } else {
            recovery_watermark
        };

        let mut data_sync_start = recovery_start;
        let mut data_size = Self::rebuild_offsets_from_anchor(
            data,
            offsets,
            items_per_section,
            offsets_bounds.start,
            recovery_start,
        )
        .await?;

        if data_size.is_none() && recovery_start != offsets_bounds.start {
            warn!(
                recovery_watermark = recovery_start,
                pruning_boundary = offsets_bounds.start,
                "crash repair: data journal shorter than offsets recovery watermark, rebuilding from pruning boundary"
            );
            data_sync_start = offsets_bounds.start;
            data_size = Self::rebuild_offsets_from_anchor(
                data,
                offsets,
                items_per_section,
                offsets_bounds.start,
                offsets_bounds.start,
            )
            .await?;
        }

        let data_size = data_size.ok_or_else(|| {
            Error::Corruption(format!(
                "data journal shorter than pruning boundary {}",
                offsets_bounds.start
            ))
        })?;

        // Final invariant checks
        let pruning_boundary = {
            let offsets_reader = offsets.reader();
            let offsets_bounds = offsets_reader.bounds();
            assert_eq!(offsets_bounds.end, data_size);

            // Recovery can truncate the data journal back to empty (e.g. an empty oldest
            // section preceded the only populated section, so no contiguous data-backed
            // prefix exists). In that case there is no oldest section to anchor against.
            if !offsets_bounds.is_empty() {
                // After alignment, offsets and data must be in the same section.
                assert_eq!(
                    offsets_bounds.start / items_per_section,
                    data_first_section,
                    "offsets and data should be in same oldest section"
                );
            }

            // Return bounds.start from offsets as the true boundary.
            offsets_bounds.start
        };

        // Rebuilt offsets are about to become durable. First make the data they point at durable
        // too; on real filesystems, init may have adopted bytes that were readable but not synced.
        Self::sync_data_range(data, data_sync_start, data_size, items_per_section).await?;
        offsets.sync().await?;
        Ok((pruning_boundary, data_size))
    }

    /// Rebuild the offsets suffix by replaying the data journal from a recovery anchor.
    ///
    /// Returns `Ok(None)` if the anchor is ahead of the data journal and callers should retry from
    /// an earlier point. If replay finds a short section after the anchor, recovery truncates newer
    /// data sections and returns the contiguous data-backed size.
    async fn rebuild_offsets_from_anchor(
        data: &mut variable::Journal<E, V>,
        offsets: &mut fixed::Journal<E, u64>,
        items_per_section: u64,
        pruning_boundary: u64,
        anchor: u64,
    ) -> Result<Option<u64>, Error> {
        assert!(
            !data.is_empty(),
            "rebuild_offsets called with empty data journal"
        );

        let offsets_bounds = {
            let offsets_reader = offsets.reader();
            offsets_reader.bounds()
        };
        if anchor < pruning_boundary || anchor > offsets_bounds.end {
            return Ok(None);
        }

        if offsets_bounds.end > anchor {
            offsets.rewind(anchor).await?;
        }

        let start_section = position_to_section(anchor, items_per_section);
        let first_position = pruning_boundary.max(start_section * items_per_section);

        let (size, repair) = {
            let skip = anchor - first_position;
            let stream = data.replay(start_section, 0, REPLAY_BUFFER_SIZE).await?;
            futures::pin_mut!(stream);

            for _ in 0..skip {
                let Some(result) = stream.next().await else {
                    return Ok(None);
                };
                let (section, ..) = result?;
                if section != start_section {
                    if section > start_section {
                        return Ok(None);
                    }
                    // section < start_section: replay-order or manager invariant violation.
                    return Err(Error::Corruption(format!(
                        "data section {section} out of order, expected section {start_section}"
                    )));
                }
            }

            let mut size = anchor;
            let mut repair = None;
            while let Some(result) = stream.next().await {
                let (section, offset, _size, _item) = result?;
                let expected_section = position_to_section(size, items_per_section);
                if section != expected_section {
                    if section > expected_section {
                        let byte_offset = data.size(expected_section).await?;
                        repair = Some((expected_section, section, size, byte_offset));
                        break;
                    }
                    // section < expected_section: over-capacity data section.
                    return Err(Error::Corruption(format!(
                        "data section {section} over capacity at logical position {size}, \
                         expected section {expected_section}"
                    )));
                }
                offsets.append(&offset).await?;
                size += 1;
            }
            (size, repair)
        };

        if let Some((section, next_section, size, byte_offset)) = repair {
            warn!(
                section,
                next_section,
                size,
                byte_offset,
                "crash repair: truncating data after short section"
            );
            data.rewind(section, byte_offset).await?;
            data.sync(section).await?;
            return Ok(Some(size));
        }

        Ok(Some(size))
    }
}

// Implement Contiguous trait for variable-length items
impl<E: Context, V: CodecShared> Contiguous for Journal<E, V> {
    type Item = V;

    async fn reader(&self) -> impl super::Reader<Item = V> + '_ {
        Self::reader(self)
    }

    async fn size(&self) -> u64 {
        Self::size(self)
    }
}

impl<E: Context, V: CodecShared> Mutable for Journal<E, V> {
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

    async fn commit(&mut self) -> Result<(), Error> {
        Self::commit(self).await
    }

    async fn sync(&mut self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Self::destroy(self).await
    }
}

#[commonware_macros::stability(ALPHA)]
impl<E: Context, V: CodecShared> crate::journal::authenticated::Inner<E> for Journal<E, V> {
    type Config = Config<V::Cfg>;

    async fn init<
        F: crate::merkle::Family,
        H: commonware_cryptography::Hasher,
        S: commonware_parallel::Strategy,
    >(
        context: E,
        merkle_cfg: crate::merkle::full::Config<S>,
        journal_cfg: Self::Config,
        rewind_predicate: fn(&V) -> bool,
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
impl<E: Context, V: CodecShared> Journal<E, V> {
    /// Test helper: Read the item at the given position.
    pub(crate) async fn read(&self, position: u64) -> Result<V, Error> {
        self.reader().read(position).await
    }

    /// Test helper: Return the bounds of the journal.
    pub(crate) fn bounds(&self) -> std::ops::Range<u64> {
        self.reader().bounds()
    }

    /// Test helper: Prune the internal data journal directly (simulates crash scenario).
    pub(crate) async fn test_prune_data(&mut self, section: u64) -> Result<bool, Error> {
        self.data.prune(section).await
    }

    /// Test helper: Prune the internal offsets journal directly (simulates crash scenario).
    pub(crate) async fn test_prune_offsets(&mut self, position: u64) -> Result<bool, Error> {
        self.offsets.prune(position).await
    }

    /// Test helper: Rewind the internal offsets journal directly (simulates crash scenario).
    pub(crate) async fn test_rewind_offsets(&mut self, position: u64) -> Result<(), Error> {
        self.offsets.rewind(position).await
    }

    /// Test helper: Set and persist the offsets recovery watermark directly.
    pub(crate) async fn test_set_offsets_recovery_watermark(
        &mut self,
        watermark: u64,
    ) -> Result<(), Error> {
        self.offsets.test_set_recovery_watermark(watermark).await
    }

    /// Test helper: Get the size of the internal offsets journal.
    pub(crate) fn test_offsets_size(&self) -> u64 {
        self.offsets.size()
    }

    /// Test helper: Rewind the internal data journal to the item at `position`.
    pub(crate) async fn test_rewind_data_to_position(
        &mut self,
        position: u64,
    ) -> Result<(), Error> {
        let offset = self.offsets.reader().read(position).await?;
        let section = position_to_section(position, self.items_per_section);
        self.data.rewind_to_offset(section, offset).await
    }

    /// Test helper: Append directly to the internal data journal (simulates crash scenario).
    pub(crate) async fn test_append_data(
        &mut self,
        section: u64,
        item: V,
    ) -> Result<(u64, u32), Error> {
        self.data.append(section, &item).await
    }

    /// Test helper: Sync the internal data journal.
    pub(crate) async fn test_sync_data(&mut self) -> Result<(), Error> {
        self.data
            .sync(self.data.newest_section().unwrap_or(0))
            .await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::tests::{partition_sync_fault, run_contiguous_tests};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::{CacheRef, Writer},
        deterministic, Blob as _, Metrics as _, Runner, Spawner as _, Storage, Supervisor as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
    use futures::FutureExt as _;
    use std::num::NonZeroU16;

    // Use some jank sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: usize = 2;
    // Larger page sizes for tests that need more buffer space.
    const LARGE_PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const SMALL_PAGE_SIZE: NonZeroU16 = NZU16!(512);

    #[test_traced]
    fn test_variable_init_syncs_adopted_data_before_offsets_watermark_advance() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-adopted-variable".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, FixedBytes<32>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            journal.append(&FixedBytes::new([1; 32])).await.unwrap();
            journal.append(&FixedBytes::new([2; 32])).await.unwrap();
            journal.sync().await.unwrap();
            // Simulate the state left by a crash after item 2's data became visible to recovery,
            // but before the offsets journal's recovery watermark advanced past item 1.
            journal
                .test_set_offsets_recovery_watermark(1)
                .await
                .unwrap();
            drop(journal);

            // Regression: init used to rebuild and sync offsets through item 2 without first
            // syncing the adopted data range they point at. A sync fault scoped only to the data
            // partition would therefore be missed. With the fix, init must sync data before the
            // rebuilt offsets become durable, so this reopen fails.
            let data_partition = format!("{}{}", cfg.partition, DATA_SUFFIX);
            let context = partition_sync_fault::Context::new(context, data_partition);
            assert!(
                Journal::<_, FixedBytes<32>>::init(context.child("second"), cfg.clone())
                    .await
                    .is_err(),
                "init must sync adopted data before advancing rebuilt offsets"
            );
        });
    }

    #[test_traced]
    fn test_variable_append_many_compressed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "append-many-compressed".into(),
                items_per_section: NZU64!(3),
                compression: Some(1),
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, FixedBytes<32>>::init(context.child("journal"), cfg)
                .await
                .unwrap();
            let items = [
                FixedBytes::new([0; 32]),
                FixedBytes::new([1; 32]),
                FixedBytes::new([2; 32]),
                FixedBytes::new([3; 32]),
                FixedBytes::new([4; 32]),
            ];

            let last = journal.append_many(Many::Flat(&items)).await.unwrap();
            assert_eq!(last, 4);
            for (pos, item) in items.iter().enumerate() {
                assert_eq!(journal.read(pos as u64).await.unwrap(), *item);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_init_at_max_size_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-max".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // The internal offsets journal rejects a maximal size, so init_at_size propagates it.
            assert!(matches!(
                Journal::<_, u64>::init_at_size(context.child("max"), cfg, u64::MAX).await,
                Err(Error::SizeOverflow)
            ));
        });
    }

    #[test_traced]
    fn test_variable_append_size_overflow() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "append-size-overflow".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize one item shy of the maximum size.
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("near_max"), cfg, u64::MAX - 1)
                    .await
                    .unwrap();

            // The first append fills the last representable position.
            assert_eq!(journal.append(&7).await.unwrap(), u64::MAX - 1);
            assert_eq!(journal.size(), u64::MAX);

            // The next append would overflow the size; it must return a recoverable error
            // rather than panicking.
            assert!(matches!(journal.append(&8).await, Err(Error::SizeOverflow)));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_read_many_after_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-after-reopen".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                ..cfg
            };
            let journal = Journal::<_, u64>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.reader();
            let items = reader.read_many(&[1, 2, 3, 7, 8, 12, 18]).await.unwrap();
            assert_eq!(items, vec![100, 200, 300, 700, 800, 1200, 1800]);
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_read_many_rejects_unsorted_positions() {
        // Non-increasing positions return an error rather than panicking.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-unsorted".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..5u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let reader = journal.reader();
            assert!(matches!(
                reader.read_many(&[2, 1]).await,
                Err(Error::PositionsNotIncreasing)
            ));
            assert!(matches!(
                reader.read_many(&[1, 1]).await,
                Err(Error::PositionsNotIncreasing)
            ));
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_read_many_consecutive_after_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-consecutive-after-reopen".into(),
                items_per_section: NZU64!(20),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                ..cfg
            };
            let journal = Journal::<_, u64>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.reader();
            let positions: Vec<u64> = (3..10).collect();
            let items = reader.read_many(&positions).await.unwrap();
            assert_eq!(items, vec![300, 400, 500, 600, 700, 800, 900]);
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    /// Test that complete offsets partition loss after pruning is detected as unrecoverable.
    ///
    /// When the offsets partition is completely lost and the data has been pruned, we cannot
    /// rebuild the index with correct position alignment (would require creating placeholder blobs).
    /// This is a genuine external failure that should be detected and reported clearly.
    #[test_traced]
    fn test_variable_offsets_partition_loss_after_prune_unrecoverable() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets-loss-after-prune".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal with data and prune ===
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections (0-3)
            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Prune to position 20 (removes sections 0-1, keeps sections 2-3)
            journal.prune(20).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.start, 20);
            assert_eq!(bounds.end, 40);

            journal.sync().await.unwrap();
            drop(journal);

            // === Phase 2: Simulate complete offsets partition loss ===
            // Remove both the offsets data partition and its metadata partition
            context
                .remove(&format!("{}-blobs", cfg.offsets_partition()), None)
                .await
                .expect("Failed to remove offsets blobs partition");
            context
                .remove(&format!("{}-metadata", cfg.offsets_partition()), None)
                .await
                .expect("Failed to remove offsets metadata partition");

            // === Phase 3: Verify this is detected as unrecoverable ===
            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Test that init aligns state when data is pruned/lost but offsets survives.
    ///
    /// This handles both:
    /// 1. Crash during prune-all (data pruned, offsets not yet)
    /// 2. External data partition loss
    ///
    /// In both cases, we align by pruning offsets to match.
    #[test_traced]
    fn test_variable_align_data_offsets_mismatch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "data-loss-test".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Setup: Create journal with data ===
            let mut variable = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 20 items across 2 sections
            for i in 0..20u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            variable.sync().await.unwrap();
            drop(variable);

            // === Simulate data loss: Delete data partition but keep offsets ===
            context
                .remove(&cfg.data_partition(), None)
                .await
                .expect("Failed to remove data partition");

            // === Verify init aligns the mismatch ===
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .expect("Should align offsets to match empty data");

            // Size should be preserved
            assert_eq!(journal.size(), 20);

            // But no items remain (both journals pruned)
            assert!(journal.bounds().is_empty());

            // All reads should fail with ItemPruned
            for i in 0..20 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            // Can append new data starting at position 20
            let pos = journal.append(&999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test replay behavior for variable-length items.
    #[test_traced]
    fn test_variable_replay() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "replay".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize journal
            let mut journal = Journal::<_, u64>::init(context, cfg).await.unwrap();

            // Append 40 items across 4 sections (0-3)
            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Test 1: Full replay
            {
                let reader = journal.reader();
                let stream = reader.replay(NZUsize!(20), 0).await.unwrap();
                futures::pin_mut!(stream);
                for i in 0..40u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(stream.next().await.is_none());
            }

            // Test 2: Partial replay from middle of section
            {
                let reader = journal.reader();
                let stream = reader.replay(NZUsize!(20), 15).await.unwrap();
                futures::pin_mut!(stream);
                for i in 15..40u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(stream.next().await.is_none());
            }

            // Test 3: Partial replay from section boundary
            {
                let reader = journal.reader();
                let stream = reader.replay(NZUsize!(20), 20).await.unwrap();
                futures::pin_mut!(stream);
                for i in 20..40u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(stream.next().await.is_none());
            }

            // Test 4: Prune and verify replay from pruned
            journal.prune(20).await.unwrap();
            {
                let reader = journal.reader();
                let res = reader.replay(NZUsize!(20), 0).await;
                assert!(matches!(res, Err(crate::journal::Error::ItemPruned(_))));
            }
            {
                let reader = journal.reader();
                let res = reader.replay(NZUsize!(20), 19).await;
                assert!(matches!(res, Err(crate::journal::Error::ItemPruned(_))));
            }

            // Test 5: Replay from exactly at pruning boundary after prune
            {
                let reader = journal.reader();
                let stream = reader.replay(NZUsize!(20), 20).await.unwrap();
                futures::pin_mut!(stream);
                for i in 20..40u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(stream.next().await.is_none());
            }

            // Test 6: Replay from the end
            {
                let reader = journal.reader();
                let stream = reader.replay(NZUsize!(20), 40).await.unwrap();
                futures::pin_mut!(stream);
                assert!(stream.next().await.is_none());
            }

            // Test 7: Replay beyond the end (should error)
            {
                let reader = journal.reader();
                let res = reader.replay(NZUsize!(20), 41).await;
                assert!(matches!(
                    res,
                    Err(crate::journal::Error::ItemOutOfRange(41))
                ));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_contiguous() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            run_contiguous_tests(move |test_name: String, idx: usize| {
                let label = test_name.replace('-', "_");
                let context = context
                    .child("test")
                    .with_attribute("name", &label)
                    .with_attribute("index", idx);
                async move {
                    let cfg = Config {
                        partition: format!("generic-test-{test_name}"),
                        items_per_section: NZU64!(10),
                        compression: None,
                        codec_config: (),
                        page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                        write_buffer: NZUsize!(1024),
                    };
                    Journal::<_, u64>::init(context, cfg).await
                }
                .boxed()
            })
            .await;
        });
    }

    /// Test multiple sequential prunes with Variable-specific guarantees.
    #[test_traced]
    fn test_variable_multiple_sequential_prunes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "sequential-prunes".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context, cfg).await.unwrap();

            // Append items across 4 sections: [0-9], [10-19], [20-29], [30-39]
            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Initial state: all items accessible
            let bounds = journal.bounds();
            assert_eq!(bounds.start, 0);
            assert_eq!(bounds.end, 40);

            // First prune: remove section 0 (positions 0-9)
            let pruned = journal.prune(10).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            assert_eq!(journal.bounds().start, 10);

            // Items 0-9 should be pruned, 10+ should be accessible
            assert!(matches!(
                journal.read(0).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Second prune: remove section 1 (positions 10-19)
            let pruned = journal.prune(20).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            assert_eq!(journal.bounds().start, 20);

            // Items 0-19 should be pruned, 20+ should be accessible
            assert!(matches!(
                journal.read(10).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert!(matches!(
                journal.read(19).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(20).await.unwrap(), 2000);
            assert_eq!(journal.read(29).await.unwrap(), 2900);

            // Third prune: remove section 2 (positions 20-29)
            let pruned = journal.prune(30).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at section boundary
            assert_eq!(journal.bounds().start, 30);

            // Items 0-29 should be pruned, 30+ should be accessible
            assert!(matches!(
                journal.read(20).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert!(matches!(
                journal.read(29).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(30).await.unwrap(), 3000);
            assert_eq!(journal.read(39).await.unwrap(), 3900);

            // Size should still be 40 (pruning doesn't affect size)
            assert_eq!(journal.size(), 40);

            journal.destroy().await.unwrap();
        });
    }

    /// Test that pruning all data and re-initializing preserves positions.
    #[test_traced]
    fn test_variable_prune_all_then_reinit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "prune-all-reinit".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal and append data ===
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..100u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert_eq!(bounds.start, 0);

            // === Phase 2: Prune all data ===
            let pruned = journal.prune(100).await.unwrap();
            assert!(pruned);

            // All data is pruned - no items remain
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert!(bounds.is_empty());

            // All reads should fail with ItemPruned
            for i in 0..100 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            journal.sync().await.unwrap();
            drop(journal);

            // === Phase 3: Re-init and verify position preserved ===
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Size should be preserved, but no items remain
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert!(bounds.is_empty());

            // All reads should still fail
            for i in 0..100 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            // === Phase 4: Append new data ===
            // Next append should get position 100
            journal.append(&10000).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 101);
            // Now we have one item at position 100
            assert_eq!(bounds.start, 100);

            // Can read the new item
            assert_eq!(journal.read(100).await.unwrap(), 10000);

            // Old positions still fail
            assert!(matches!(
                journal.read(99).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery from crash after data journal pruned but before offsets journal.
    #[test_traced]
    fn test_variable_recovery_prune_crash_offsets_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                partition: "recovery-prune-crash".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections to both journals
            for i in 0..40u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            // Prune to position 10 normally (both data and offsets journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.bounds().start, 10);

            // === Simulate crash: Prune data journal but not offsets journal ===
            // Manually prune data journal to section 2 (position 20)
            variable.test_prune_data(2).await.unwrap();
            // Offsets journal still has data from position 10-19

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: offsets journal pruned to match data journal
            let bounds = variable.bounds();
            assert_eq!(bounds.start, 20);
            assert_eq!(bounds.end, 40);

            // Reads before position 20 should fail (pruned from both journals)
            assert!(matches!(
                variable.read(10).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));

            // Reads at position 20+ should succeed
            assert_eq!(variable.read(20).await.unwrap(), 2000);
            assert_eq!(variable.read(39).await.unwrap(), 3900);

            variable.destroy().await.unwrap();
        });
    }

    /// Test recovery detects corruption when offsets journal pruned ahead of data journal.
    ///
    /// Simulates an impossible state (offsets journal pruned more than data journal) which
    /// should never happen due to write ordering. Verifies that init() returns corruption error.
    #[test_traced]
    fn test_variable_recovery_offsets_ahead_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                partition: "recovery-offsets-ahead".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 40 items across 4 sections to both journals
            for i in 0..40u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            // Prune offsets journal ahead of data journal (impossible state)
            variable.test_prune_offsets(20).await.unwrap(); // Prune to position 20
            variable.test_prune_data(1).await.unwrap(); // Only prune data journal to section 1 (position 10)

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify corruption detected ===
            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Offsets journal is empty but in a different section than data. This is an impossible state:
    /// both journals are always created in the same section by init or init_at_size.
    #[test_traced]
    fn test_variable_recovery_offsets_empty_different_section_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets-empty-diff-section".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..15u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Clear offsets to section 2 (position 20) while data starts at section 0.
            // This puts them in different sections with offsets empty (bounds 20..20).
            journal.offsets.clear_to_size(20).await.unwrap();
            drop(journal);

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Offsets journal ends before data oldest position (offsets_bounds.end < data_oldest_pos).
    /// This is an impossible/corrupted state.
    #[test_traced]
    fn test_variable_recovery_offsets_end_behind_data_oldest_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets-end-behind-data-oldest".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..15u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune data to section 1 (position 10), but rewind offsets to 5 (so offsets_bounds is 0..5).
            // offsets_bounds.end = 5 < data_oldest_pos = 10.
            journal.test_prune_data(1).await.unwrap();
            journal.test_rewind_offsets(5).await.unwrap();
            drop(journal);

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Offsets start is mid-section ahead of data's section-aligned start, but in the same
    /// section. This is the valid state left by init_at_size.
    #[test_traced]
    fn test_variable_recovery_offsets_start_mid_section_ahead_of_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets-mid-section-ahead".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // init_at_size(7) creates offsets starting at position 7 (mid-section 0), while
            // data's first section is section 0 (position 0). offsets.start > data_oldest_pos
            // but same section.
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..5u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..12);
            assert_eq!(journal.read(7).await.unwrap(), 0);
            assert_eq!(journal.read(11).await.unwrap(), 400);
            journal.destroy().await.unwrap();
        });
    }

    /// The offsets recovery watermark is below the offsets pruning boundary. This can happen if
    /// prune moved the boundary forward but sync (which advances the watermark) didn't run.
    /// Recovery falls back to rebuilding from the offsets start.
    #[test_traced]
    fn test_variable_recovery_watermark_below_offsets_start() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "watermark-below-start".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune to section 1 (position 10), then set watermark below the new start.
            journal.prune(10).await.unwrap();
            journal
                .test_set_offsets_recovery_watermark(5)
                .await
                .unwrap();
            drop(journal);

            // Recovery detects stale watermark and rebuilds from offsets start.
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 10..25);
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(24).await.unwrap(), 2400);
            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery from crash after appending to data journal but before appending to offsets journal.
    #[test_traced]
    fn test_variable_recovery_append_crash_offsets_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with partial data ===
            let cfg = Config {
                partition: "recovery-append-crash".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 15 items to both journals (fills section 0, partial section 1)
            for i in 0..15u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            assert_eq!(variable.size(), 15);

            // Manually append 5 more items directly to data journal only
            for i in 15..20u64 {
                variable.test_append_data(1, i * 100).await.unwrap();
            }
            // Offsets journal still has only 15 entries

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init should rebuild offsets journal from data journal replay
            let bounds = variable.bounds();
            assert_eq!(bounds.end, 20);
            assert_eq!(bounds.start, 0);

            // All items should be readable from both journals
            for i in 0..20u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }

            // Offsets journal should be fully rebuilt to match data journal
            assert_eq!(variable.test_offsets_size(), 20);

            variable.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_rejects_overlong_data_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-overlong-data-section".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..11u64 {
                journal.test_append_data(0, i * 100).await.unwrap();
            }
            journal.test_sync_data().await.unwrap();
            drop(journal);

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Over-capacity non-newest data section detected during offset rebuild replay.
    /// The preflight check (items_in_last_section) only validates the newest section. This test
    /// overfills section 0, adds a valid section 1, and leaves offsets empty so rebuild_offsets
    /// replays from section 0 and hits the over-capacity branch.
    #[test_traced]
    fn test_variable_recovery_rejects_over_capacity_non_newest_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-over-capacity-non-newest".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Overfill section 0 with 11 items (capacity is 10).
            for i in 0..11u64 {
                journal.test_append_data(0, i * 100).await.unwrap();
            }
            // Add one valid item in section 1 so section 0 is not the newest.
            journal.test_append_data(1, 9999).await.unwrap();
            // Sync both sections so the data survives reopen.
            journal.data.sync(0).await.unwrap();
            journal.data.sync(1).await.unwrap();
            // Offsets is empty, so rebuild replays from section 0.
            drop(journal);

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_variable_recovery_handles_multiple_empty_data_tail_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config::<()> {
                partition: "recovery-empty-data-tail".into(),
                items_per_section: NZU64!(1),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // First persist a prefix, then append across multiple section
            // boundaries without syncing. The unsynced item bytes are lost when
            // the journal is dropped, but their section blobs remain visible.
            assert_eq!(journal.append(&10).await.unwrap(), 0);
            journal.sync().await.unwrap();
            assert_eq!(journal.append(&20).await.unwrap(), 1);
            assert_eq!(journal.append(&30).await.unwrap(), 2);
            drop(journal);

            let data_partition = cfg.data_partition();
            let data_blobs = context.scan(&data_partition).await.unwrap();
            assert_eq!(data_blobs.len(), 3);
            for name in &data_blobs[1..] {
                let (_blob, size) = context.open(&data_partition, name).await.unwrap();
                assert_eq!(size, 0);
            }

            // Recovery should trim only the empty trailing sections, preserving
            // the durable prefix.
            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                ..cfg
            };
            let mut journal = Journal::<_, u64>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..1);
            assert_eq!(journal.read(0).await.unwrap(), 10);
            assert_eq!(journal.append(&42).await.unwrap(), 1);
            assert_eq!(journal.read(1).await.unwrap(), 42);
            drop(journal);

            // Recovery should have removed the empty trailing sections, leaving
            // only the durable prefix's section and the one written above.
            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(data_blobs.len(), 2);

            let journal = Journal::<_, u64>::init(context.child("recovered"), cfg)
                .await
                .unwrap();
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_handles_empty_data_with_no_durable_items() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config::<()> {
                partition: "recovery-empty-data-no-items".into(),
                items_per_section: NZU64!(1),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // Append across multiple section boundaries without ever syncing. Each
            // append opens a fresh section blob, but no item bytes (and no offsets)
            // become durable, so recovery sees multiple empty sections and no
            // durable data.
            assert_eq!(journal.append(&10).await.unwrap(), 0);
            assert_eq!(journal.append(&20).await.unwrap(), 1);
            drop(journal);

            let data_partition = cfg.data_partition();
            let data_blobs = context.scan(&data_partition).await.unwrap();
            assert_eq!(data_blobs.len(), 2);
            for name in &data_blobs {
                let (_blob, size) = context.open(&data_partition, name).await.unwrap();
                assert_eq!(size, 0);
            }

            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                ..cfg
            };
            let mut journal = Journal::<_, u64>::init(context.child("recovered"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            assert_eq!(journal.append(&42).await.unwrap(), 0);
            assert_eq!(journal.read(0).await.unwrap(), 42);
            journal.destroy().await.unwrap();
        });
    }

    /// Test that a durable data section above the sync watermark, sitting beyond an empty
    /// intermediate section, is rolled back to the contiguous boundary during recovery.
    ///
    /// Since #3790 removed the append-time sync when crossing blob boundaries, a process crash can
    /// leave a later data section incidentally durable (its page-cache writes survived) while an
    /// earlier section stayed buffered and was lost, producing a physical gap. Recovery anchors at
    /// the durable watermark and replays the data forward with a strict section-contiguity check, so
    /// the post-gap section is truncated and recovery returns only the synced prefix.
    #[test_traced]
    fn test_variable_recovery_rolls_back_durable_section_after_gap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-rollback-after-gap".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Durably commit section 0 (positions 0..10), advancing the recovery watermark to 10.
            for i in 0..10u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Append sections 1 and 2 without committing. Manually sync only section 2's data blob
            // to mimic its page-cache writes surviving a crash, while section 1 stays buffered and
            // the offsets journal is never advanced past position 10.
            for i in 10..30u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.data.sync(2).await.unwrap();
            drop(journal);

            // Durable state: section 0 (10 items), section 1 (empty, lost), section 2 (10 items).
            let data_partition = cfg.data_partition();
            let mut names = context.scan(&data_partition).await.unwrap();
            names.sort();
            assert_eq!(names.len(), 3);
            let sizes = {
                let mut sizes = Vec::new();
                for name in &names {
                    let (_blob, size) = context.open(&data_partition, name).await.unwrap();
                    sizes.push(size);
                }
                sizes
            };
            assert!(sizes[0] > 0, "section 0 should be durable");
            assert_eq!(sizes[1], 0, "section 1 should be the gap");
            assert!(sizes[2] > 0, "section 2 should be incidentally durable");

            // Recovery rolls back to the watermark boundary: only the synced prefix survives and the
            // gapped section 2 is truncated away.
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..10);
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(10).await,
                Err(Error::ItemOutOfRange(10))
            ));

            // The orphaned section 2 is gone. The repair truncates section 1 in place, so its
            // emptied blob remains as the recovered tail.
            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(data_blobs.len(), 2);

            // Appends resume cleanly from the recovered boundary.
            assert_eq!(journal.append(&1234).await.unwrap(), 10);
            assert_eq!(journal.read(10).await.unwrap(), 1234);

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest data section is empty but a newer section still holds
    /// durable items and the offsets journal is gone.
    ///
    /// A contiguous journal can only populate a later section after filling the earlier one, so an
    /// empty oldest section with a populated newer section is an orphaned gap. Replaying from the
    /// empty oldest section immediately yields the newer section's items, which are "ahead" of the
    /// expected section, so recovery truncates everything past the gap and aligns the journal to
    /// empty. This regresses a bad invariant that asserted offsets must be non-empty after
    /// alignment.
    #[test_traced]
    fn test_variable_recovery_empty_oldest_section_orphaned_newer_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-empty-oldest-section".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // Durably persist sections 0 and 1 (positions 0..20).
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Empty the oldest data section in place, leaving section 1's items orphaned past the
            // gap, then drop the offsets journal so recovery rebuilds from the data alone.
            let data_partition = cfg.data_partition();
            let mut names = context.scan(&data_partition).await.unwrap();
            names.sort();
            assert_eq!(names.len(), 2);
            let (section0, size0) = context.open(&data_partition, &names[0]).await.unwrap();
            assert!(size0 > 0, "section 0 should start durable");
            section0.resize(0).await.unwrap();
            section0.sync().await.unwrap();
            context
                .remove(&format!("{}-blobs", cfg.offsets_partition()), None)
                .await
                .unwrap();
            context
                .remove(&format!("{}-metadata", cfg.offsets_partition()), None)
                .await
                .unwrap();

            // Recovery aligns to an empty journal instead of panicking.
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            assert!(matches!(
                journal.read(0).await,
                Err(Error::ItemOutOfRange(0))
            ));

            // The orphaned newer section is truncated away and appends resume from position 0.
            assert_eq!(journal.append(&42).await.unwrap(), 0);
            assert_eq!(journal.read(0).await.unwrap(), 42);
            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(
                data_blobs.len(),
                1,
                "orphaned newer section should be truncated away"
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest data section ends at a clean page boundary but is still short.
    ///
    /// No trailing bytes are repaired in this case: the data section simply contains fewer complete
    /// items than its capacity. Replaying from the start must still detect the jump to the newer
    /// section and truncate it instead of skipping missing logical positions.
    #[test_traced]
    fn test_variable_recovery_clean_short_oldest_section_orphaned_newer_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-clean-short-oldest-section".into(),
                items_per_section: NZU64!(64),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // Build two durable data sections. Section 1 is only reachable if replay incorrectly
            // skips the missing tail of section 0.
            let mut journal =
                Journal::<_, FixedBytes<31>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            for i in 0..128u8 {
                journal.append(&FixedBytes::new([i; 31])).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let physical_page_size = LARGE_PAGE_SIZE.get() as u64 + 12;
            let items_in_page = LARGE_PAGE_SIZE.get() as u64 / 32;
            assert!(items_in_page < cfg.items_per_section.get());

            let data_partition = cfg.data_partition();
            let mut names = context.scan(&data_partition).await.unwrap();
            names.sort();
            assert_eq!(names.len(), 2);

            // Truncate at a valid physical page boundary. This leaves a clean short data section,
            // not trailing corruption.
            let (section0, size0) = context.open(&data_partition, &names[0]).await.unwrap();
            assert!(size0 > physical_page_size);
            section0.resize(physical_page_size).await.unwrap();
            section0.sync().await.unwrap();

            // Remove offsets so recovery must rebuild by replaying data and checking section
            // continuity.
            context
                .remove(&format!("{}-blobs", cfg.offsets_partition()), None)
                .await
                .unwrap();
            context
                .remove(&format!("{}-metadata", cfg.offsets_partition()), None)
                .await
                .unwrap();

            // Recovery must stop at the short non-tail section rather than accepting section 1's
            // items as later logical positions.
            let mut journal =
                Journal::<_, FixedBytes<31>>::init(context.child("second"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 0..items_in_page);
            assert_eq!(
                journal.read(items_in_page - 1).await.unwrap(),
                FixedBytes::new([(items_in_page - 1) as u8; 31])
            );
            assert!(matches!(
                journal.read(items_in_page).await,
                Err(Error::ItemOutOfRange(pos)) if pos == items_in_page
            ));

            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(
                data_blobs.len(),
                1,
                "orphaned newer section should be truncated away"
            );

            // Appends resume directly after the recovered prefix.
            assert_eq!(
                journal.append(&FixedBytes::new([42; 31])).await.unwrap(),
                items_in_page
            );
            assert_eq!(
                journal.read(items_in_page).await.unwrap(),
                FixedBytes::new([42; 31])
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test that a crash partway through a multi-section sync leaves a contiguous durable prefix
    /// that recovery preserves.
    ///
    /// `flush_dirty_data` syncs dirty data sections before syncing offsets. This reproduces a
    /// crash after sections 0 and 1 were synced but before section 2 and the offsets journal were,
    /// then asserts recovery keeps exactly the contiguous prefix 0..20.
    #[test_traced]
    fn test_variable_recovery_partial_sync_loop_keeps_contiguous_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-partial-sync-loop".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Fill sections 0 and 1 and partially fill section 2 (positions 20..25). Nothing is
            // synced yet, so only the created section blobs are durable, all still empty.
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Sync sections 0 and 1 but not section 2 (and not offsets), simulating a crash after
            // part of a multi-section sync became durable.
            journal.data.sync(0).await.unwrap();
            journal.data.sync(1).await.unwrap();
            drop(journal);

            // The durable data is exactly the contiguous prefix: sections 0 and 1 hold items,
            // section 2 is an empty trailing blob, and offsets never synced.
            let data_partition = cfg.data_partition();
            let mut names = context.scan(&data_partition).await.unwrap();
            names.sort();
            assert_eq!(names.len(), 3);
            for (section, name) in names.iter().enumerate() {
                let (_blob, size) = context.open(&data_partition, name).await.unwrap();
                if section < 2 {
                    assert!(size > 0, "section {section} should be durable");
                } else {
                    assert_eq!(size, 0, "section {section} should be empty");
                }
            }

            // Recovery trims the empty trailing section, rebuilds offsets from the durable data, and
            // exposes exactly the contiguous prefix 0..20.
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..20);
            for i in 0..20u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(20))
            ));

            // The trailing section is gone and appends continue from the recovered tail.
            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(data_blobs.len(), 2);
            assert_eq!(journal.append(&2000).await.unwrap(), 20);
            assert_eq!(journal.read(20).await.unwrap(), 2000);

            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery from multiple prune operations with crash.
    #[test_traced]
    fn test_variable_recovery_multiple_prunes_crash() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data ===
            let cfg = Config {
                partition: "recovery-multiple-prunes".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 50 items across 5 sections to both journals
            for i in 0..50u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            // Prune to position 10 normally (both data and offsets journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.bounds().start, 10);

            // === Simulate crash: Multiple prunes on data journal, not on offsets journal ===
            // Manually prune data journal to section 3 (position 30)
            variable.test_prune_data(3).await.unwrap();
            // Offsets journal still thinks oldest is position 10

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: offsets journal pruned to match data journal
            let bounds = variable.bounds();
            assert_eq!(bounds.start, 30);
            assert_eq!(bounds.end, 50);

            // Reads before position 30 should fail (pruned from both journals)
            assert!(matches!(
                variable.read(10).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert!(matches!(
                variable.read(20).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));

            // Reads at position 30+ should succeed
            assert_eq!(variable.read(30).await.unwrap(), 3000);
            assert_eq!(variable.read(49).await.unwrap(), 4900);

            variable.destroy().await.unwrap();
        });
    }

    /// Test recovery when the offsets journal is behind the data journal.
    ///
    /// This creates a situation where offsets are missing while the data journal still contains
    /// items across multiple sections. Verifies that init() rebuilds the offsets suffix across all
    /// remaining data sections.
    #[test_traced]
    fn test_variable_recovery_offsets_behind_data_multi_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data across multiple sections ===
            let cfg = Config {
                partition: "recovery-rewind-crash".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut variable = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 25 items across 3 sections (section 0: 0-9, section 1: 10-19, section 2: 20-24)
            for i in 0..25u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            assert_eq!(variable.size(), 25);

            // Keep offsets for positions 0-4, while data still contains all 25 items.
            variable.test_rewind_offsets(5).await.unwrap();

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let mut variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init should rebuild offsets[5-24] from data journal across all 3 sections
            let bounds = variable.bounds();
            assert_eq!(bounds.end, 25);
            assert_eq!(bounds.start, 0);

            // All items should be readable - offsets rebuilt correctly across all sections
            for i in 0..25u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }

            // Verify offsets journal fully rebuilt
            assert_eq!(variable.test_offsets_size(), 25);

            // Verify next append gets position 25
            let pos = variable.append(&2500).await.unwrap();
            assert_eq!(pos, 25);
            assert_eq!(variable.read(25).await.unwrap(), 2500);

            variable.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_rebuild_offsets_anchor_outside_bounds_returns_none() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let data_cfg = variable::Config {
                partition: "rebuild-anchor-outside-data".into(),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let offsets_cfg = fixed::Config {
                partition: "rebuild-anchor-outside-offsets".into(),
                items_per_blob: NZU64!(10),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut data = variable::Journal::<_, u64>::init(context.child("data"), data_cfg)
                .await
                .unwrap();
            let mut offsets = fixed::Journal::<_, u64>::init(context.child("offsets"), offsets_cfg)
                .await
                .unwrap();

            let (offset, _) = data.append(0, &100).await.unwrap();
            offsets.append(&offset).await.unwrap();

            let result =
                Journal::<_, u64>::rebuild_offsets_from_anchor(&mut data, &mut offsets, 10, 0, 2)
                    .await
                    .unwrap();
            assert!(result.is_none());

            data.destroy().await.unwrap();
            offsets.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_retries_from_pruning_boundary_when_anchor_too_far() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-anchor-too-far".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // The offsets watermark is in-bounds, but the data journal is shorter than that
            // anchor. Recovery should retry from the pruning boundary and rebuild only the
            // retained data prefix.
            journal
                .test_set_offsets_recovery_watermark(15)
                .await
                .unwrap();
            journal.test_rewind_data_to_position(12).await.unwrap();
            journal.test_sync_data().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            assert_eq!(journal.test_offsets_size(), 12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(12).await,
                Err(Error::ItemOutOfRange(12))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_retries_from_pruning_boundary_after_short_middle_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-short-middle-retry".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..30u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Keep the offsets watermark in bounds and within the retained data end bound, but make
            // the data section that contains the watermark too short to reach it.
            journal
                .test_set_offsets_recovery_watermark(15)
                .await
                .unwrap();
            journal.test_rewind_data_to_position(12).await.unwrap();
            journal.test_sync_data().await.unwrap();
            journal.test_append_data(2, 9999).await.unwrap();
            journal.test_sync_data().await.unwrap();
            drop(journal);

            // The first rebuild from watermark 15 starts in section 1 and tries to skip five items,
            // but section 1 contains only positions 10 and 11 before replay jumps to section 2.
            // That should return Ok(None), retry from the pruning boundary, and then truncate the
            // orphaned section 2.
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            assert_eq!(journal.test_offsets_size(), 12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(12).await,
                Err(Error::ItemOutOfRange(12))
            ));

            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(
                data_blobs.len(),
                2,
                "orphaned section 2 should be truncated away"
            );

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_rewind_commit_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "rewind-commit-reopen".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            journal.rewind(12).await.unwrap();
            journal.commit().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(12).await,
                Err(Error::ItemOutOfRange(12))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_boundary_data_rewind_rebuilds_offsets() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-boundary-data-rewind".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            journal.test_rewind_data_to_position(10).await.unwrap();
            journal.test_sync_data().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..10);
            assert_eq!(journal.test_offsets_size(), 10);
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(10).await,
                Err(Error::ItemOutOfRange(10))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_truncates_short_data_section_after_anchor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-short-section-after-anchor".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Simulate a crash after the previous recovery checkpoint where section 1 was only
            // partly durable but section 2 was present. Recovery should keep the contiguous prefix
            // and discard section 2 rather than treating the section jump as hard corruption.
            journal
                .test_set_offsets_recovery_watermark(10)
                .await
                .unwrap();
            let offset = {
                let offsets = journal.offsets.reader();
                offsets.read(12).await.unwrap()
            };
            journal.data.rewind_section(1, offset).await.unwrap();
            journal.data.sync(1).await.unwrap();
            journal.data.sync(2).await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            assert_eq!(journal.test_offsets_size(), 12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                journal.read(12).await,
                Err(Error::ItemOutOfRange(12))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_init_persists_offsets_trailing_item_repair() {
        let executor = deterministic::Runner::default();
        let ((offsets_blob_partition, expected_size), checkpoint) =
            executor.start_and_recover(|context| async move {
                let cfg = Config {
                    partition: "offsets-init-repair-sync".into(),
                    items_per_section: NZU64!(10),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                };
                let offsets_blob_partition = format!("{}-blobs", cfg.offsets_partition());
                let expected_size = 2 * std::mem::size_of::<u64>() as u64;

                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                journal.append(&10).await.unwrap();
                journal.append(&20).await.unwrap();
                journal.sync().await.unwrap();
                drop(journal);

                let (blob, raw_size) = context
                    .open(&offsets_blob_partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let append = Writer::new(
                    blob,
                    raw_size,
                    2048,
                    CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                )
                .await
                .unwrap();
                assert_eq!(append.size().await, expected_size);
                append.resize(expected_size + 1).await.unwrap();
                append.sync().await.unwrap();
                drop(append);

                let journal = Journal::<_, u64>::init(context.child("second"), cfg)
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 0..2);
                drop(journal);

                (offsets_blob_partition, expected_size)
            });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            let (blob, raw_size) = context
                .open(&offsets_blob_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            let append = Writer::new(
                blob,
                raw_size,
                2048,
                CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
            )
            .await
            .unwrap();
            assert_eq!(append.size().await, expected_size);
        });
    }

    #[test_traced]
    fn test_variable_init_persists_data_tail_repair() {
        let executor = deterministic::Runner::default();
        let ((data_partition, expected_size), checkpoint) =
            executor.start_and_recover(|context| async move {
                let cfg = Config {
                    partition: "data-init-repair-sync".into(),
                    items_per_section: NZU64!(10),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                    write_buffer: NZUsize!(1024),
                };
                let data_partition = cfg.data_partition();

                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                journal.append(&10).await.unwrap();
                journal.append(&20).await.unwrap();
                journal.sync().await.unwrap();
                drop(journal);

                let (blob, raw_size) = context
                    .open(&data_partition, &0u64.to_be_bytes())
                    .await
                    .unwrap();
                let append = Writer::new(
                    blob,
                    raw_size,
                    2048,
                    CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                )
                .await
                .unwrap();
                let expected_size = append.size().await;
                append.append(&[0xFF, 0xFF]).await.unwrap();
                append.sync().await.unwrap();
                drop(append);

                let journal = Journal::<_, u64>::init(context.child("second"), cfg)
                    .await
                    .unwrap();
                assert_eq!(journal.bounds(), 0..2);
                drop(journal);

                (data_partition, expected_size)
            });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            let (blob, raw_size) = context
                .open(&data_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            let append = Writer::new(
                blob,
                raw_size,
                2048,
                CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
            )
            .await
            .unwrap();
            assert_eq!(append.size().await, expected_size);
        });
    }

    /// Test recovery from crash after data sync but before offsets sync when journal was
    /// previously emptied by pruning.
    #[test_traced]
    fn test_variable_recovery_empty_offsets_after_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-empty-after-prune".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Phase 1: Create journal with one full section ===
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 10 items (positions 0-9), fills section 0
            for i in 0..10u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 0);

            // === Phase 2: Prune to create empty journal ===
            journal.prune(10).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert!(bounds.is_empty()); // Empty!

            // === Phase 3: Append directly to data journal to simulate crash ===
            // Manually append to data journal only (bypassing Variable's append logic)
            // This simulates the case where data was synced but offsets wasn't
            for i in 10..20u64 {
                journal.test_append_data(1, i * 100).await.unwrap();
            }
            // Sync the data journal (section 1)
            journal.test_sync_data().await.unwrap();
            // Do NOT sync offsets journal - simulates crash before offsets.sync()

            // Close without syncing offsets
            drop(journal);

            // === Phase 4: Verify recovery succeeds ===
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .expect("Should recover from crash after data sync but before offsets sync");

            // All data should be recovered
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 20);
            assert_eq!(bounds.start, 10);

            // All items from position 10-19 should be readable
            for i in 10..20u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            // Items 0-9 should be pruned
            for i in 0..10 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Test that offsets index is rebuilt from data after sync writes data but not offsets.
    #[test_traced]
    fn test_variable_concurrent_sync_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "concurrent-sync-recovery".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append items across a section boundary
            for i in 0..15u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Manually sync only data to simulate crash during concurrent sync
            journal.commit().await.unwrap();

            // Simulate a crash (offsets not synced)
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Data should be intact and offsets rebuilt
            assert_eq!(journal.size(), 15);
            for i in 0..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_from_mid_section_durable_anchor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "mid-section-durable-anchor".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            assert_eq!(journal.append(&700).await.unwrap(), 7);
            journal.sync().await.unwrap();

            for i in 1..6u64 {
                assert_eq!(journal.append(&(700 + i)).await.unwrap(), 7 + i);
            }
            journal.commit().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..13);
            for i in 0..6u64 {
                assert_eq!(journal.read(7 + i).await.unwrap(), 700 + i);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-zero".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("storage"), cfg.clone(), 0)
                    .await
                    .unwrap();

            // Size should be 0
            assert_eq!(journal.size(), 0);

            // No oldest retained position (empty journal)
            assert!(journal.bounds().is_empty());

            // Next append should get position 0
            let pos = journal.append(&100).await.unwrap();
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);
            assert_eq!(journal.read(0).await.unwrap(), 100);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_section_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-boundary".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 10 (exactly at section 1 boundary with items_per_section=5)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("storage"), cfg.clone(), 10)
                    .await
                    .unwrap();

            // Size should be 10
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);

            // No data yet, so no oldest retained position
            assert!(bounds.is_empty());

            // Next append should get position 10
            let pos = journal.append(&1000).await.unwrap();
            assert_eq!(pos, 10);
            assert_eq!(journal.size(), 11);
            assert_eq!(journal.read(10).await.unwrap(), 1000);

            // Can continue appending
            let pos = journal.append(&1001).await.unwrap();
            assert_eq!(pos, 11);
            assert_eq!(journal.read(11).await.unwrap(), 1001);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_mid_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-mid".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (middle of section 1 with items_per_section=5)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("storage"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Size should be 7
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 7);

            // No data yet, so no oldest retained position
            assert!(bounds.is_empty());

            // Next append should get position 7
            let pos = journal.append(&700).await.unwrap();
            assert_eq!(pos, 7);
            assert_eq!(journal.size(), 8);
            assert_eq!(journal.read(7).await.unwrap(), 700);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-persist".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 15
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 15)
                    .await
                    .unwrap();

            // Append some items
            for i in 0..5u64 {
                let pos = journal.append(&(1500 + i)).await.unwrap();
                assert_eq!(pos, 15 + i);
            }

            assert_eq!(journal.size(), 20);

            // Sync and reopen
            journal.sync().await.unwrap();
            drop(journal);

            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Size and data should be preserved
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 20);
            assert_eq!(bounds.start, 15);

            // Verify data
            for i in 0..5u64 {
                assert_eq!(journal.read(15 + i).await.unwrap(), 1500 + i);
            }

            // Can continue appending
            let pos = journal.append(&9999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 9999);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_persistence_without_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-persist-empty".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 15
            let journal = Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 15)
                .await
                .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 15);
            assert!(bounds.is_empty());

            // Drop without writing any data
            drop(journal);

            // Reopen and verify size persisted
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 15);
            assert!(bounds.is_empty());

            // Can append starting at position 15
            let pos = journal.append(&1500).await.unwrap();
            assert_eq!(pos, 15);
            assert_eq!(journal.read(15).await.unwrap(), 1500);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_clears_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-clears-existing".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..12u64 {
                journal.append(&(100 + i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("reset"), cfg.clone(), 7)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 7..7);
            assert_eq!(journal.append(&700).await.unwrap(), 7);
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..8);
            assert_eq!(journal.read(7).await.unwrap(), 700);
            assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));
            assert!(matches!(
                journal.read(8).await,
                Err(Error::ItemOutOfRange(8))
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_stages_reset_before_clearing_data() {
        let partition = "init-at-size-stage-before-clear-failure".to_string();
        let executor = deterministic::Runner::default();
        let ((), checkpoint) = executor.start_and_recover({
            let partition = partition.clone();
            |context| async move {
                let cfg = Config {
                    partition,
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                    write_buffer: NZUsize!(1024),
                };

                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..12u64 {
                    journal.append(&(100 + i)).await.unwrap();
                }
                journal.sync().await.unwrap();
                drop(journal);

                *context.storage_fault_config().write() = deterministic::FaultConfig {
                    sync_rate: Some(1.0),
                    ..Default::default()
                };
                assert!(
                    Journal::<_, u64>::init_at_size(context.child("reset"), cfg, 7)
                        .await
                        .is_err()
                );
            }
        });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = Config {
                partition,
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let journal = Journal::<_, u64>::init(context.child("recover"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), 100 + i);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_clear_to_size_stages_reset_before_clearing_data() {
        let partition = "clear-to-size-stage-before-clear-failure".to_string();
        let executor = deterministic::Runner::default();
        let ((), checkpoint) = executor.start_and_recover({
            let partition = partition.clone();
            |context| async move {
                let cfg = Config {
                    partition,
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                    write_buffer: NZUsize!(1024),
                };

                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..12u64 {
                    journal.append(&(100 + i)).await.unwrap();
                }
                journal.sync().await.unwrap();

                // Fail the offsets metadata sync inside `stage_clear_intent` so `clear_to_size`
                // aborts before any data is cleared. The reset intent never becomes durable.
                *context.storage_fault_config().write() = deterministic::FaultConfig {
                    sync_rate: Some(1.0),
                    ..Default::default()
                };
                assert!(journal.clear_to_size(7).await.is_err());
            }
        });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = Config {
                partition,
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let journal = Journal::<_, u64>::init(context.child("recover"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), 100 + i);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_clear_to_size_crash_after_staging_completes_on_init() {
        let partition = "clear-to-size-crash-after-staging".to_string();
        let executor = deterministic::Runner::default();
        let ((), checkpoint) = executor.start_and_recover({
            let partition = partition.clone();
            |context| async move {
                let cfg = Config {
                    partition,
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                    write_buffer: NZUsize!(1024),
                };

                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..12u64 {
                    journal.append(&(100 + i)).await.unwrap();
                }
                journal.sync().await.unwrap();

                // Let `stage_clear_intent` (a metadata sync) persist the reset intent, but fail the
                // subsequent `data.clear()` (a blob remove) so `clear_to_size` aborts after the
                // intent is durable but before the data is cleared.
                *context.storage_fault_config().write() = deterministic::FaultConfig {
                    remove_rate: Some(1.0),
                    ..Default::default()
                };
                assert!(journal.clear_to_size(7).await.is_err());
            }
        });

        deterministic::Runner::from(checkpoint).start(move |context| async move {
            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            let cfg = Config {
                partition,
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // `init` finds the staged intent, discards the stale data, and completes the reset.
            let mut journal = Journal::<_, u64>::init(context.child("recover"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..7);
            assert_eq!(journal.append(&700).await.unwrap(), 7);
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen: the completed reset persists and no stale data was replayed.
            let journal = Journal::<_, u64>::init(context.child("reopen"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..8);
            assert_eq!(journal.read(7).await.unwrap(), 700);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_recovers_staged_reset_crash_points() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            for (index, clear_data) in [false, true].into_iter().enumerate() {
                let cfg = Config {
                    partition: format!("init-at-size-staged-reset-crash-{index}"),
                    items_per_section: NZU64!(5),
                    compression: None,
                    codec_config: (),
                    page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                    write_buffer: NZUsize!(1024),
                };

                let mut journal = Journal::<_, u64>::init(
                    context.child("first").with_attribute("index", index),
                    cfg.clone(),
                )
                .await
                .unwrap();
                for i in 0..12u64 {
                    journal.append(&(100 + i)).await.unwrap();
                }
                journal.sync().await.unwrap();
                drop(journal);

                let offsets_cfg = fixed::Config {
                    partition: cfg.offsets_partition(),
                    items_per_blob: cfg.items_per_section,
                    page_cache: cfg.page_cache.clone(),
                    write_buffer: cfg.write_buffer,
                };
                // Simulate a crash mid-`init_at_size`: stage a clear intent in the offsets
                // checkpoint but leave data untouched (clear_data=false) or also clear data
                // (clear_data=true) so we cover both crash points.
                let intent_ctx = context.child("intent").with_attribute("index", index);
                fixed::Journal::<_, u64>::test_stage_clear(
                    intent_ctx.child("meta"),
                    &offsets_cfg.partition,
                    7,
                )
                .await
                .unwrap();

                if clear_data {
                    let mut data = variable::Journal::<_, u64>::init(
                        context.child("data").with_attribute("index", index),
                        variable::Config {
                            partition: cfg.data_partition(),
                            compression: cfg.compression,
                            codec_config: cfg.codec_config,
                            page_cache: cfg.page_cache.clone(),
                            write_buffer: cfg.write_buffer,
                        },
                    )
                    .await
                    .unwrap();
                    data.clear().await.unwrap();
                }

                let mut journal = Journal::<_, u64>::init(
                    context.child("recover").with_attribute("index", index),
                    cfg.clone(),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 7..7);
                assert_eq!(journal.append(&700).await.unwrap(), 7);
                journal.sync().await.unwrap();
                drop(journal);

                let journal = Journal::<_, u64>::init(
                    context.child("reopen").with_attribute("index", index),
                    cfg.clone(),
                )
                .await
                .unwrap();
                assert_eq!(journal.bounds(), 7..8);
                assert_eq!(journal.read(7).await.unwrap(), 700);

                journal.destroy().await.unwrap();
            }
        });
    }

    #[test_traced]
    fn test_init_at_size_overwrites_pending_clear_target() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-overwrites-pending-target".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..12u64 {
                journal.append(&(100 + i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Simulate a prior `clear_to_size(5)` that crashed after staging its intent: the offsets
            // checkpoint carries a clear target of 5 while the data journal still holds all 12 items.
            let offsets_cfg = fixed::Config {
                partition: cfg.offsets_partition(),
                items_per_blob: cfg.items_per_section,
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            };
            let stale_ctx = context.child("stale");
            fixed::Journal::<_, u64>::test_stage_clear(
                stale_ctx.child("meta"),
                &offsets_cfg.partition,
                5,
            )
            .await
            .unwrap();

            // init_at_size(10) overwrites the pending target of 5 and resets to 10.
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("reset"), cfg.clone(), 10)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 10..10);
            assert_eq!(journal.append(&700).await.unwrap(), 10);
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen: target 10 (not 5) persisted and no stale data was replayed.
            let journal = Journal::<_, u64>::init(context.child("reopen"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 10..11);
            assert_eq!(journal.read(10).await.unwrap(), 700);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_discards_same_section_stale_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-discards-same-section-stale-data".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 5)
                    .await
                    .unwrap();
            for i in 0..4u64 {
                assert_eq!(journal.append(&(500 + i)).await.unwrap(), 5 + i);
            }
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init_at_size(context.child("reset"), cfg.clone(), 7)
                .await
                .unwrap();
            drop(journal);

            let mut journal = Journal::<_, u64>::init(context.child("after_reset"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..7);
            assert!(matches!(
                journal.read(7).await,
                Err(Error::ItemOutOfRange(7))
            ));

            assert_eq!(journal.append(&700).await.unwrap(), 7);
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("after_append"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 7..8);
            assert_eq!(journal.read(7).await.unwrap(), 700);
            assert!(matches!(
                journal.read(8).await,
                Err(Error::ItemOutOfRange(8))
            ));

            journal.destroy().await.unwrap();
        });
    }

    /// Test init_at_size with mid-section value persists correctly across restart.
    #[test_traced]
    fn test_init_at_size_mid_section_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-mid-section".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (mid-section, 7 % 5 = 2)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 3 items at positions 7, 8, 9 (fills rest of section 1)
            for i in 0..3u64 {
                let pos = journal.append(&(700 + i)).await.unwrap();
                assert_eq!(pos, 7 + i);
            }

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 7);

            // Sync and reopen
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Size and bounds.start should be preserved correctly
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 7);

            // Verify data
            for i in 0..3u64 {
                assert_eq!(journal.read(7 + i).await.unwrap(), 700 + i);
            }

            // Positions before 7 should be pruned
            assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));

            journal.destroy().await.unwrap();
        });
    }

    /// Test init_at_size mid-section with data spanning multiple sections.
    #[test_traced]
    fn test_init_at_size_mid_section_multi_section_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-multi-section".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (mid-section)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 8 items: positions 7-14 (section 1: 3 items, section 2: 5 items)
            for i in 0..8u64 {
                let pos = journal.append(&(700 + i)).await.unwrap();
                assert_eq!(pos, 7 + i);
            }

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 15);
            assert_eq!(bounds.start, 7);

            // Sync and reopen
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Verify state preserved
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 15);
            assert_eq!(bounds.start, 7);

            // Verify all data
            for i in 0..8u64 {
                assert_eq!(journal.read(7 + i).await.unwrap(), 700 + i);
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Regression test: data-empty crash repair must preserve mid-section pruning boundary.
    #[test_traced]
    fn test_align_journals_data_empty_mid_section_pruning_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "align-journals-mid-section-pruning-boundary".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Phase 1: Create data and offsets, then simulate data-only pruning crash.
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&(100 + i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Simulate crash after data was cleared but before offsets were pruned.
            journal.data.clear().await.unwrap();
            drop(journal);

            // Phase 2: Init triggers data-empty repair and should treat journal as fully pruned at size 7.
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 7);
            assert!(bounds.is_empty());

            // Append one item at position 7.
            let pos = journal.append(&777).await.unwrap();
            assert_eq!(pos, 7);
            assert_eq!(journal.size(), 8);
            assert_eq!(journal.read(7).await.unwrap(), 777);

            // Sync only the data journal to simulate a crash before offsets are synced.
            let section = 7 / cfg.items_per_section.get();
            journal.data.sync(section).await.unwrap();
            drop(journal);

            // Phase 3: Reopen and verify we did not lose the appended item.
            let journal = Journal::<_, u64>::init(context.child("third"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 8);
            assert_eq!(bounds.start, 7);
            assert_eq!(journal.read(7).await.unwrap(), 777);

            journal.destroy().await.unwrap();
        });
    }

    /// Test crash recovery: init_at_size + append + crash with data synced but offsets not.
    #[test_traced]
    fn test_init_at_size_crash_data_synced_offsets_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-crash-recovery".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (mid-section)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 3 items
            for i in 0..3u64 {
                journal.append(&(700 + i)).await.unwrap();
            }

            // Sync only the data journal, not offsets (simulate crash)
            journal.data.sync(1).await.unwrap();
            // Don't sync offsets - simulates crash after data write but before offsets write
            drop(journal);

            // Reopen - should recover by rebuilding offsets from data
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Verify recovery
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 7);

            // Verify data is accessible
            for i in 0..3u64 {
                assert_eq!(journal.read(7 + i).await.unwrap(), 700 + i);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_prune_does_not_move_oldest_retained_backwards() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "prune-no-backwards".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append a few items at positions 7..9
            for i in 0..3u64 {
                let pos = journal.append(&(700 + i)).await.unwrap();
                assert_eq!(pos, 7 + i);
            }
            assert_eq!(journal.bounds().start, 7);

            // Prune to a position within the same section should not move bounds.start backwards.
            journal.prune(8).await.unwrap();
            assert_eq!(journal.bounds().start, 7);
            assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));
            assert_eq!(journal.read(7).await.unwrap(), 700);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_large_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-large".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at a large position (position 1000)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("storage"), cfg.clone(), 1000)
                    .await
                    .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 1000);
            // No data yet, so no oldest retained position
            assert!(bounds.is_empty());

            // Next append should get position 1000
            let pos = journal.append(&100000).await.unwrap();
            assert_eq!(pos, 1000);
            assert_eq!(journal.read(1000).await.unwrap(), 100000);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_at_size_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-prune".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 20
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("storage"), cfg.clone(), 20)
                    .await
                    .unwrap();

            // Append items 20-29
            for i in 0..10u64 {
                journal.append(&(2000 + i)).await.unwrap();
            }

            assert_eq!(journal.size(), 30);

            // Prune to position 25
            journal.prune(25).await.unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 30);
            assert_eq!(bounds.start, 25);

            // Verify remaining items are readable
            for i in 25..30u64 {
                assert_eq!(journal.read(i).await.unwrap(), 2000 + (i - 20));
            }

            // Continue appending
            let pos = journal.append(&3000).await.unwrap();
            assert_eq!(pos, 30);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is no existing data on disk.
    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-fresh-start".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Initialize journal with sync boundaries when no existing data exists
            let lower_bound = 10;
            let upper_bound = 26;
            let mut journal = Journal::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with sync boundaries");

            let bounds = journal.bounds();
            assert_eq!(bounds.end, lower_bound);
            assert!(bounds.is_empty());

            // Append items using the contiguous API
            let pos1 = journal.append(&42u64).await.unwrap();
            assert_eq!(pos1, lower_bound);
            assert_eq!(journal.read(pos1).await.unwrap(), 42u64);

            let pos2 = journal.append(&43u64).await.unwrap();
            assert_eq!(pos2, lower_bound + 1);
            assert_eq!(journal.read(pos2).await.unwrap(), 43u64);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when there is existing data that overlaps with the sync target range.
    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-overlap".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data in multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-19 (sections 0-3 with items_per_section=5)
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that overlap with existing data
            // lower_bound: 8 (section 1), upper_bound: 31 (last location 30, section 6)
            let lower_bound = 8;
            let upper_bound = 31;
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with overlap");

            assert_eq!(journal.size(), 20);

            // Verify oldest retained is pruned to lower_bound's section boundary (5)
            assert_eq!(journal.bounds().start, 5); // Section 1 starts at position 5

            // Verify data integrity: positions before 5 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(4).await, Err(Error::ItemPruned(_))));

            // Positions 5-19 should be accessible
            assert_eq!(journal.read(5).await.unwrap(), 500);
            assert_eq!(journal.read(8).await.unwrap(), 800);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Position 20+ should not exist yet
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new items
            let pos = journal.append(&999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with invalid parameters.
    #[should_panic]
    #[test_traced]
    fn test_init_sync_invalid_parameters() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-invalid".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            #[allow(clippy::reversed_empty_ranges)]
            let _result = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg,
                10..5, // invalid range: lower > upper
            )
            .await;
        });
    }

    /// Test `init_sync` when existing data exactly matches the sync range.
    #[test_traced]
    fn test_init_sync_existing_data_exact_match() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test-exact-match".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data exactly matching sync range
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-19 (sections 0-3 with items_per_section=5)
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that exactly match existing data
            let lower_bound = 5; // section 1
            let upper_bound = 20; // section 3
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            assert_eq!(journal.size(), 20);

            // Verify pruning to lower bound (section 1 boundary = position 5)
            assert_eq!(journal.bounds().start, 5); // Section 1 starts at position 5

            // Verify positions before 5 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(4).await, Err(Error::ItemPruned(_))));

            // Positions 5-19 should be accessible
            assert_eq!(journal.read(5).await.unwrap(), 500);
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Position 20+ should not exist yet
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new operations
            let pos = journal.append(&999).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when existing data exceeds the sync target range.
    /// This tests that ItemOutOfRange is returned when existing data goes beyond the upper bound.
    #[test_traced]
    fn test_init_sync_existing_data_exceeds_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test-unexpected-data".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with data beyond sync range
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("initial"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-29 (sections 0-5 with items_per_section=5)
            for i in 0..30u64 {
                journal.append(&(i * 1000)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that are exceeded by existing data
            let lower_bound = 8; // section 1
            for (i, upper_bound) in (9..29).enumerate() {
                let result = Journal::<deterministic::Context, u64>::init_sync(
                    context.child("sync").with_attribute("index", i),
                    cfg.clone(),
                    lower_bound..upper_bound,
                )
                .await;

                // Should return ItemOutOfRange error since data exists beyond upper_bound
                assert!(matches!(result, Err(Error::ItemOutOfRange(_))));
            }
        });
    }

    /// Test `init_sync` repairs an empty journal recovered at a stale position beyond the range.
    #[test_traced]
    fn test_init_sync_empty_stale_position_beyond_upper_bound() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-empty-stale-position".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            let stale_size = 30;
            let journal = Journal::<deterministic::Context, u64>::init_at_size(
                context.child("first"),
                cfg.clone(),
                stale_size,
            )
            .await
            .expect("Failed to create stale empty journal");
            assert_eq!(journal.size(), stale_size);
            assert!(journal.bounds().is_empty());
            drop(journal);

            let lower_bound = 10;
            let upper_bound = 26;
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("second"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to repair stale empty journal");

            assert_eq!(journal.size(), lower_bound);
            assert!(journal.bounds().is_empty());

            let pos = journal.append(&999).await.unwrap();
            assert_eq!(pos, lower_bound);
            assert_eq!(journal.read(pos).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` repairs an empty journal recovered after a `clear_to_size` crash.
    #[test_traced]
    fn test_init_sync_recovers_from_stale_clear_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "test-stale-clear-to-size".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            let mut journal = Journal::<deterministic::Context, u64>::init_at_size(
                context.child("first"),
                cfg.clone(),
                9,
            )
            .await
            .expect("Failed to create stale empty journal");
            journal.sync().await.unwrap();
            drop(journal);

            // Simulate clear_to_size(7) crashing after clearing data, but before offsets were
            // re-cleared. Recovery will initially see the old empty offsets boundary at 9.
            match context.remove(&cfg.data_partition(), None).await {
                Ok(()) | Err(commonware_runtime::Error::PartitionMissing(_)) => {}
                Err(error) => panic!("failed to clear data partition: {error}"),
            }

            let lower_bound = 7;
            let upper_bound = 20;
            let journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("second"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to repair stale empty journal");

            assert_eq!(journal.size(), lower_bound);
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, lower_bound);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when all existing data is stale (before lower bound).
    #[test_traced]
    fn test_init_sync_existing_data_stale() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test-stale".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create initial journal with stale data
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-9 (sections 0-1 with items_per_section=5)
            for i in 0..10u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries beyond all existing data
            let lower_bound = 15; // section 3
            let upper_bound = 26; // last element in section 5
            let journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("second"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with stale data");

            assert_eq!(journal.size(), 15);

            // Verify fresh journal (all old data destroyed, starts at position 15)
            assert!(journal.bounds().is_empty());

            // Verify old positions don't exist
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(_))));

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` with section boundary edge cases.
    #[test_traced]
    fn test_init_sync_section_boundaries() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test-boundaries".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data at section boundaries
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-24 (sections 0-4 with items_per_section=5)
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Test sync boundaries exactly at section boundaries
            let lower_bound = 15; // Exactly at section boundary (15/5 = 3)
            let upper_bound = 25; // Last element exactly at section boundary (24/5 = 4)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal at boundaries");

            assert_eq!(journal.size(), 25);

            // Verify oldest retained is at section 3 boundary (position 15)
            assert_eq!(journal.bounds().start, 15);

            // Verify positions before 15 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(_))));

            // Verify positions 15-24 are accessible
            assert_eq!(journal.read(15).await.unwrap(), 1500);
            assert_eq!(journal.read(20).await.unwrap(), 2000);
            assert_eq!(journal.read(24).await.unwrap(), 2400);

            // Position 25+ should not exist yet
            assert!(matches!(
                journal.read(25).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new operations
            let pos = journal.append(&999).await.unwrap();
            assert_eq!(pos, 25);
            assert_eq!(journal.read(25).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test `init_sync` when range.start and range.end-1 are in the same section.
    #[test_traced]
    fn test_init_sync_same_section_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test-same-section".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data in multiple sections
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-14 (sections 0-2 with items_per_section=5)
            for i in 0..15u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Test sync boundaries within the same section
            let lower_bound = 10; // operation 10 (section 2: 10/5 = 2)
            let upper_bound = 15; // Last operation 14 (section 2: 14/5 = 2)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with same-section bounds");

            assert_eq!(journal.size(), 15);

            // Both operations are in section 2, so sections 0, 1 should be pruned, section 2 retained
            // Oldest retained position should be at section 2 boundary (position 10)
            assert_eq!(journal.bounds().start, 10);

            // Verify positions before 10 are pruned
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(_))));
            assert!(matches!(journal.read(9).await, Err(Error::ItemPruned(_))));

            // Verify positions 10-14 are accessible
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(11).await.unwrap(), 1100);
            assert_eq!(journal.read(14).await.unwrap(), 1400);

            // Position 15+ should not exist yet
            assert!(matches!(
                journal.read(15).await,
                Err(Error::ItemOutOfRange(_))
            ));

            // Assert journal can accept new operations
            let pos = journal.append(&999).await.unwrap();
            assert_eq!(pos, 15);
            assert_eq!(journal.read(15).await.unwrap(), 999);

            journal.destroy().await.unwrap();
        });
    }

    /// Test contiguous variable journal with items_per_section=1.
    ///
    /// This is a regression test for a bug where reading from size()-1 fails
    /// when using items_per_section=1, particularly after pruning and restart.
    #[test_traced]
    fn test_single_item_per_section() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "single-item-per-section".into(),
                items_per_section: NZU64!(1),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // === Test 1: Basic single item operation ===
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Verify empty state
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 0);
            assert!(bounds.is_empty());

            // Append 1 item (value = position * 100, so position 0 has value 0)
            let pos = journal.append(&0).await.unwrap();
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);

            // Sync
            journal.sync().await.unwrap();

            // Read from size() - 1
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, 0);

            // === Test 2: Multiple items with single item per section ===
            for i in 1..10u64 {
                let pos = journal.append(&(i * 100)).await.unwrap();
                assert_eq!(pos, i);
                assert_eq!(journal.size(), i + 1);

                // Verify we can read the just-appended item at size() - 1
                let value = journal.read(journal.size() - 1).await.unwrap();
                assert_eq!(value, i * 100);
            }

            // Verify all items can be read
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.sync().await.unwrap();

            // === Test 3: Pruning with single item per section ===
            // Prune to position 5 (removes positions 0-4)
            let pruned = journal.prune(5).await.unwrap();
            assert!(pruned);

            // Size should still be 10
            assert_eq!(journal.size(), 10);

            // bounds.start should be 5
            assert_eq!(journal.bounds().start, 5);

            // Reading from bounds.end - 1 (position 9) should still work
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, 900);

            // Reading from pruned positions should return ItemPruned
            for i in 0..5 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            // Reading from retained positions should work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            // Append more items after pruning
            for i in 10..15u64 {
                let pos = journal.append(&(i * 100)).await.unwrap();
                assert_eq!(pos, i);

                // Verify we can read from size() - 1
                let value = journal.read(journal.size() - 1).await.unwrap();
                assert_eq!(value, i * 100);
            }

            journal.sync().await.unwrap();
            drop(journal);

            // === Test 4: Restart persistence with single item per section ===
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Verify size is preserved
            assert_eq!(journal.size(), 15);

            // Verify bounds.start is preserved
            assert_eq!(journal.bounds().start, 5);

            // Reading from bounds.end - 1 should work after restart
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, 1400);

            // Reading all retained positions should work
            for i in 5..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.destroy().await.unwrap();

            // === Test 5: Restart after pruning with non-zero index (KEY SCENARIO) ===
            // Fresh journal for this test
            let mut journal = Journal::<_, u64>::init(context.child("third"), cfg.clone())
                .await
                .unwrap();

            // Append 10 items (positions 0-9)
            for i in 0..10u64 {
                journal.append(&(i * 1000)).await.unwrap();
            }

            // Prune to position 5 (removes positions 0-4)
            journal.prune(5).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 5);

            // Sync and restart
            journal.sync().await.unwrap();
            drop(journal);

            // Re-open journal
            let journal = Journal::<_, u64>::init(context.child("fourth"), cfg.clone())
                .await
                .unwrap();

            // Verify state after restart
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 5);

            // KEY TEST: Reading from bounds.end - 1 (position 9) should work
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, 9000);

            // Verify all retained positions (5-9) work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 1000);
            }

            journal.destroy().await.unwrap();

            // === Test 6: Prune all items (edge case) ===
            // This tests the scenario where prune removes everything.
            // Callers must check bounds().is_empty() before reading.
            let mut journal = Journal::<_, u64>::init(context.child("fifth"), cfg.clone())
                .await
                .unwrap();

            for i in 0..5u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune all items
            journal.prune(5).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 5); // Size unchanged
            assert!(bounds.is_empty()); // All pruned

            // bounds.end - 1 = 4, but position 4 is pruned
            let result = journal.read(journal.size() - 1).await;
            assert!(matches!(result, Err(crate::journal::Error::ItemPruned(4))));

            // After appending, reading works again
            journal.append(&500).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.start, 5);
            assert_eq!(journal.read(bounds.end - 1).await.unwrap(), 500);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_journal_clear_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "clear-test".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // Append 25 items (spanning multiple sections)
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 25);
            assert_eq!(bounds.start, 0);
            journal.sync().await.unwrap();

            // Clear to position 100, effectively resetting the journal
            journal.clear_to_size(100).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert!(bounds.is_empty());

            // Old positions should fail
            for i in 0..25 {
                assert!(matches!(
                    journal.read(i).await,
                    Err(crate::journal::Error::ItemPruned(_))
                ));
            }

            // Verify size persists after restart without writing any data
            drop(journal);
            let mut journal =
                Journal::<_, u64>::init(context.child("journal_after_clear"), cfg.clone())
                    .await
                    .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert!(bounds.is_empty());

            // Append new data starting at position 100
            for i in 100..105u64 {
                let pos = journal.append(&(i * 100)).await.unwrap();
                assert_eq!(pos, i);
            }
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 105);
            assert_eq!(bounds.start, 100);

            // New positions should be readable
            for i in 100..105u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            // Sync and re-init to verify persistence
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("journal_reopened"), cfg)
                .await
                .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 105);
            assert_eq!(bounds.start, 100);
            for i in 100..105u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_journal_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "metrics".into(),
                items_per_section: NZU64!(2),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("variable_metrics"), cfg)
                .await
                .unwrap();

            let items = [0, 1, 2, 3, 4];
            journal.append_many(Many::Flat(&items)).await.unwrap();
            journal.append(&5).await.unwrap();
            let reader = journal.reader();
            reader.read(0).await.unwrap();
            reader.read_many(&[1, 2]).await.unwrap();
            reader.try_read_sync(3).unwrap();
            drop(reader);
            journal.commit().await.unwrap();
            journal.sync().await.unwrap();
            journal.prune(2).await.unwrap();
            journal.rewind(4).await.unwrap();

            let buffer = context.encode();
            for expected in [
                "variable_metrics_size 4",
                "variable_metrics_pruning_boundary 2",
                "variable_metrics_retained 2",
                "variable_metrics_tail_items 2",
                "variable_metrics_append_calls_total 1",
                "variable_metrics_append_many_calls_total 1",
                "variable_metrics_read_calls_total 1",
                "variable_metrics_read_many_calls_total 1",
                "variable_metrics_try_read_sync_hits_total 1",
                "variable_metrics_items_read_total 4",
                "variable_metrics_commit_calls_total 1",
                "variable_metrics_sync_calls_total 1",
                "variable_metrics_append_duration_count 1",
                "variable_metrics_append_many_duration_count 1",
                "variable_metrics_read_duration_count 0",
                "variable_metrics_read_many_duration_count 1",
                "variable_metrics_commit_duration_count 1",
                "variable_metrics_sync_duration_count 1",
                "variable_metrics_data_tracked",
                "variable_metrics_offsets_size 4",
                "variable_metrics_offsets_blobs_tracked",
            ] {
                assert!(buffer.contains(expected), "{expected}\n{buffer}");
            }
            for unexpected in [
                "variable_metrics_cache_hits_total",
                "variable_metrics_cache_misses_total",
            ] {
                assert!(!buffer.contains(unexpected), "{unexpected}\n{buffer}");
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_journal_read_miss_timed() {
        // Reads served from storage record a read_duration sample; cache hits do not.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Sections span multiple full pages so their data must go through the (evictable)
            // page cache rather than staying resident in each blob's partial tail page.
            let cfg = Config {
                partition: "miss".into(),
                items_per_section: NZU64!(50),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("miss"), cfg)
                .await
                .unwrap();
            for i in 0..200u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();

            // The page cache cannot hold every page, so some position must be cold.
            let reader = journal.reader();
            let pos = (0..200)
                .find(|&pos| reader.try_read_sync(pos).is_none())
                .expect("some position should be cold");
            assert_eq!(reader.read(pos).await.unwrap(), pos);
            drop(reader);

            let buffer = context.encode();
            assert!(buffer.contains("miss_read_duration_count 1"), "{buffer}");

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_snapshot_frozen_across_roll() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "snapshot-frozen".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            let snapshot = journal.reader();
            assert_eq!(snapshot.bounds(), 0..7);

            // Appending past the section boundary rolls the snapshot's tail blob into
            // history; the snapshot keeps reading it through its own handle.
            for i in 7..23u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            assert_eq!(snapshot.bounds(), 0..7);
            for i in 0..7u64 {
                assert_eq!(snapshot.read(i).await.unwrap(), i * 100);
            }
            assert!(matches!(
                snapshot.read(7).await,
                Err(Error::ItemOutOfRange(7))
            ));

            let fresh = journal.reader();
            assert_eq!(fresh.bounds(), 0..23);
            assert_eq!(fresh.read(22).await.unwrap(), 2200);

            drop(snapshot);
            drop(fresh);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_prune_under_snapshot() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "snapshot-prune".into(),
                items_per_section: NZU64!(5),
                compression: Some(3),
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..17u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let snapshot = journal.reader();
            assert!(journal.prune(12).await.unwrap());

            // The straggler reads the pruned range through its own handles.
            assert_eq!(snapshot.bounds(), 0..17);
            for i in 0..17u64 {
                assert_eq!(snapshot.read(i).await.unwrap(), i * 100);
            }
            assert_eq!(
                snapshot.read_many(&[1, 2, 3, 11, 16]).await.unwrap(),
                vec![100, 200, 300, 1100, 1600]
            );

            let fresh = journal.reader();
            assert_eq!(fresh.bounds(), 10..17);
            assert!(matches!(fresh.read(3).await, Err(Error::ItemPruned(3))));

            drop(snapshot);
            drop(fresh);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_rewind_sealed_blob_in_use() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "snapshot-rewind-sealed".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..12u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let snapshot = journal.reader();
            assert!(matches!(journal.rewind(3).await, Err(Error::BlobInUse(0))));

            // The refused rewind left the journal fully usable and had no side effects.
            assert_eq!(snapshot.read(11).await.unwrap(), 1100);
            drop(snapshot);

            journal.rewind(3).await.unwrap();
            assert_eq!(journal.bounds(), 0..3);
            for i in 3..9u64 {
                assert_eq!(journal.append(&(i + 100)).await.unwrap(), i);
            }
            assert_eq!(journal.read(8).await.unwrap(), 108);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_rewind_tail_blocked_while_snapshot_live() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "snapshot-rewind-tail".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..8u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // A live snapshot blocks the tail rewind (it would tear the snapshot's bytes once
            // the rewound offsets are reappended).
            let snapshot = journal.reader();
            assert!(matches!(journal.rewind(2).await, Err(Error::BlobInUse(_))));
            // The snapshot still reads its original, unchanged bytes.
            assert_eq!(snapshot.read(6).await.unwrap(), 600);

            // After the snapshot drops, the rewind succeeds and reappends reuse the offsets.
            drop(snapshot);
            journal.rewind(2).await.unwrap();
            for i in 2..8u64 {
                journal.append(&(i + 100)).await.unwrap();
            }

            // A fresh reader observes the new data; no stale reader is alive to see torn bytes.
            let fresh = journal.reader();
            assert_eq!(fresh.read(6).await.unwrap(), 106);
            assert_eq!(fresh.read(1).await.unwrap(), 100);

            drop(fresh);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_snapshots_readable_during_concurrent_appends() {
        let executor = deterministic::Runner::seeded(7);
        executor.start(|context| async move {
            let cfg = Config {
                partition: "snapshot-concurrent".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();

            let (mut tx, mut rx) =
                futures::channel::mpsc::channel::<Reader<deterministic::Context, u64>>(8);
            let validator = context.child("validator").spawn(|_| async move {
                let mut validated = 0usize;
                while let Some(snapshot) = rx.next().await {
                    let bounds = snapshot.bounds();
                    for i in bounds.clone() {
                        assert_eq!(snapshot.read(i).await.unwrap(), i * 100);
                    }
                    validated += (bounds.end - bounds.start) as usize;
                }
                validated
            });

            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
                if i % 7 == 0 {
                    let snapshot = journal.reader();
                    if tx.try_send(snapshot).is_err() {
                        break;
                    }
                }
            }
            drop(tx);
            assert!(validator.await.unwrap() > 0);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_replay_from_stale_snapshot() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "snapshot-replay".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Positions 5..7 live in the snapshot's tail blob.
            let snapshot = journal.reader();
            assert_eq!(snapshot.bounds(), 0..7);

            // Roll the snapshot's tail into history, then prune both of its blobs away.
            for i in 7..23u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            assert!(journal.prune(12).await.unwrap());

            {
                let stream = snapshot.replay(NZUsize!(1024), 0).await.unwrap();
                futures::pin_mut!(stream);
                let mut expected = 0u64;
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(pos, expected);
                    assert_eq!(item, pos * 100);
                    expected += 1;
                }
                assert_eq!(expected, 7);
            }

            drop(snapshot);
            journal.destroy().await.unwrap();
        });
    }
}
