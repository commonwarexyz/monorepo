//! Position-based journal for variable-length items.
//!
//! Items are stored as varint-framed records in data blobs. A parallel offsets journal (a
//! [fixed::Journal] of `u64`s) records, for each position, the byte offset one past its frame's
//! end within its data blob: frame `i` spans `[entry[i - 1], entry[i])`, with the first frame of
//! each data blob starting at byte 0. Storing frame ends makes every crash repair a bounded
//! binary search plus resize (see [Journal::init]).

use super::{
    blob_first_position,
    blobs::{Blob, Blobs, Partition, Replay as BlobReplay, Writable},
    fixed,
    metrics::Metrics,
    position_to_blob, Contiguous, Many, Mutable,
};
#[commonware_macros::stability(ALPHA)]
use crate::{journal::authenticated, merkle};
use crate::{
    journal::{
        frame::{
            decode_item, decode_length_prefix, encode_frame_into, find_frame, read_frame_at,
            FrameInfo,
        },
        Error,
    },
    Context,
};
use commonware_codec::{varint::MAX_U32_VARINT_SIZE, Codec, CodecShared};
use commonware_macros::boxed;
use commonware_runtime::{
    buffer::paged::{CacheRef, Writer},
    Blob as RBlob, Buf, IoBuf, WriteBatch as _,
};
use futures::{future::try_join_all, Stream};
use std::{
    collections::BTreeMap,
    io::Cursor,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
};
#[commonware_macros::stability(ALPHA)]
use tracing::debug;
use tracing::warn;

/// Items encoded for a deferred append, created by [`Journal::prepare_append`] and consumed by
/// [`Journal::append_prepared`].
pub struct PreparedAppend<V> {
    encoded: Vec<u8>,
    item_starts: Vec<usize>,
    compressed: bool,
    _marker: PhantomData<V>,
}

/// Suffix appended to the base partition name for the data blobs.
const DATA_SUFFIX: &str = "_data";

/// Suffix appended to the base partition name for the offsets journal.
const OFFSETS_SUFFIX: &str = "_offsets";

/// Decode one varint-framed item from the head of `bytes`, whose encoded length must be exactly
/// `frame_len` (the gap to the next frame's offset). Returns `None` on any mismatch or decode
/// failure. The async read path reports such errors.
fn decode_frame_from_span<V: CodecShared>(
    bytes: &[u8],
    frame_len: usize,
    codec_config: &V::Cfg,
    compressed: bool,
) -> Option<V> {
    let mut cursor = Cursor::new(bytes);
    let (size, varint_len) = decode_length_prefix(&mut cursor).ok()?;
    let actual_len = size.checked_add(varint_len)?;
    if actual_len != frame_len || frame_len > bytes.len() {
        return None;
    }
    decode_item::<V>(&bytes[varint_len..frame_len], codec_config, compressed).ok()
}

/// Return the first retained position stored in `blob`, given the journal's pruning boundary.
///
/// The frame for this position starts at byte 0 of the data blob: pruning is blob-aligned, and a
/// mid-blob boundary (from `init_at_size`) starts a fresh blob.
fn first_position_in_blob(bounds_start: u64, blob: u64, items_per_blob: u64) -> Result<u64, Error> {
    Ok(blob_first_position(blob, items_per_blob)?.max(bounds_start))
}

/// Replay state for one data blob in a variable-size journal.
///
/// Unlike fixed replay, each yielded item must first decode a varint frame length. The byte
/// `budget` caps how much frame data this state emits in one stream batch.
struct ReplayState<'a, B: RBlob, V: Codec> {
    /// Blob index, used in corruption messages.
    blob: u64,
    /// Sequential logical bytes for this blob.
    replay: BlobReplay<'a, B>,
    /// Target maximum number of encoded bytes decoded per batch.
    budget: u64,
    /// Next position to yield.
    pos: u64,
    /// Exclusive end position within this blob.
    end_pos: u64,
    /// Byte offset of the next frame in this blob.
    offset: u64,
    /// Codec configuration for decoded items.
    codec_config: V::Cfg,
    /// Whether frame payloads are compressed.
    compressed: bool,
    _marker: PhantomData<V>,
}

impl<B: RBlob, V: CodecShared> super::ReplayBatchState for ReplayState<'_, B, V> {
    type Item = V;

    /// Decode the next batch of varint-framed items from this blob.
    async fn next_batch(mut self) -> Option<(Vec<Result<(u64, V), Error>>, Self)> {
        if self.pos == self.end_pos {
            return None;
        }

        let mut batch = Vec::new();
        let mut consumed = 0u64;
        loop {
            if self.pos == self.end_pos {
                return (!batch.is_empty()).then_some((batch, self));
            }

            // A short read before a frame header is corruption for replay: bounds and offsets say
            // this item exists, so EOF here means the data blob is shorter than expected.
            match self.replay.ensure(MAX_U32_VARINT_SIZE).await {
                Ok(true) => {}
                Ok(false) if self.replay.remaining() == 0 => {
                    batch.push(Err(Error::Corruption(format!(
                        "data blob {} ended before position {}",
                        self.blob, self.pos
                    ))));
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
                Ok(false) => {}
                Err(err) => {
                    batch.push(Err(err));
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
            }

            let before_remaining = self.replay.remaining();
            let (item_size, varint_len) = match decode_length_prefix(&mut self.replay) {
                Ok(result) => result,
                Err(err) => {
                    if self.replay.is_exhausted() || before_remaining < MAX_U32_VARINT_SIZE {
                        batch.push(Err(Error::Corruption(format!(
                            "incomplete frame header in data blob {} at offset {}",
                            self.blob, self.offset
                        ))));
                    } else {
                        batch.push(Err(err));
                    }
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
            };

            match self.replay.ensure(item_size).await {
                Ok(true) => {}
                Ok(false) => {
                    batch.push(Err(Error::Corruption(format!(
                        "incomplete frame in data blob {} at offset {}",
                        self.blob, self.offset
                    ))));
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
                Err(err) => {
                    batch.push(Err(err));
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
            }

            let next_offset = self
                .offset
                .checked_add(varint_len as u64)
                .and_then(|offset| offset.checked_add(item_size as u64));
            let Some(next_offset) = next_offset else {
                batch.push(Err(Error::OffsetOverflow));
                self.pos = self.end_pos;
                return Some((batch, self));
            };
            let item_len = next_offset - self.offset;

            // `take(item_size)` advances past exactly the payload bytes after the header was
            // consumed by `decode_length_prefix`.
            match decode_item::<V>(
                (&mut self.replay).take(item_size),
                &self.codec_config,
                self.compressed,
            ) {
                Ok(item) => {
                    let pos = self.pos;
                    let Some(next_pos) = self.pos.checked_add(1) else {
                        batch.push(Err(Error::OffsetOverflow));
                        self.pos = self.end_pos;
                        return Some((batch, self));
                    };
                    self.pos = next_pos;
                    self.offset = next_offset;
                    consumed = match consumed.checked_add(item_len) {
                        Some(consumed) => consumed,
                        None => {
                            batch.push(Err(Error::OffsetOverflow));
                            self.pos = self.end_pos;
                            return Some((batch, self));
                        }
                    };
                    batch.push(Ok((pos, item)));
                }
                Err(err) => {
                    batch.push(Err(err));
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
            }

            // Yield once the replay byte budget is reached. If fewer than MAX_U32_VARINT_SIZE
            // bytes remain, yield as well so the next poll can refill before decoding a header.
            if consumed >= self.budget {
                return Some((batch, self));
            }
            if self.replay.remaining() < MAX_U32_VARINT_SIZE {
                return Some((batch, self));
            }
        }
    }
}

/// Configuration for a [Journal].
#[derive(Clone)]
pub struct Config<C> {
    /// Base partition name. Sub-partitions will be created by appending DATA_SUFFIX and OFFSETS_SUFFIX.
    pub partition: String,

    /// The number of items to store in each blob.
    ///
    /// Once set, this value cannot be changed across restarts.
    /// All non-final blobs are logically full.
    pub items_per_section: NonZeroU64,

    /// Optional compression level for stored items.
    pub compression: Option<u8>,

    /// [Codec] configuration for encoding/decoding items.
    pub codec_config: C,

    /// Page cache for buffering reads from the underlying storage.
    pub page_cache: CacheRef,

    /// Write buffer size for each blob.
    pub write_buffer: NonZeroUsize,
}

impl<C> Config<C> {
    /// Returns the partition name for the data blobs.
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
/// This journal manages blob assignment automatically, allowing callers to append items
/// sequentially without manually tracking blob indexes.
///
/// # Crash consistency
///
/// The storage backend restores every blob to exactly its last-synced state after a crash, so
/// torn frames cannot exist, so a frame that fails to decode is corruption. The offsets journal and
/// the data blobs may still diverge across a crash, but every mutation orders its syncs so that
/// the durable offsets entries and durable data bytes always describe prefixes of one shared
/// history:
///
/// * Appends sync the data blob then the offsets blob at each rollover, and `commit`/`sync` sync
///   data before offsets, so either side may simply be ahead of the other.
/// * `rewind` makes both truncations durable before returning, so post-rewind appends can never
///   pair stale entries with rewritten bytes (see [Journal::rewind]).
/// * `prune` removes data blobs before pruning the offsets journal.
///
/// Init then reconciles the two sides with bounded repairs (no frame scanning):
/// * Offsets starting behind the oldest data blob are pruned forward to match (prune crash).
/// * Offsets ahead of the durable data are rewound to the largest entry the data backs (found by
///   binary search within the last indexed blob), and unindexed data past the entries is
///   truncated. Data blobs past the recovered tail are removed.
/// * Anything else (offsets ending behind the oldest data blob, offsets starting in a later blob
///   than the data, non-monotone entries, mis-sized interior blobs) is corruption.
pub struct Journal<E: Context, V: Codec> {
    /// The data blobs: sealed history plus the writable tail.
    blobs: Writable<E>,

    /// Index mapping each position to the byte offset one past its frame's end within its data
    /// blob. A frame starts where its predecessor ends (byte 0 for the first frame of a blob).
    offsets: fixed::Journal<E, u64>,

    /// The readable positions; `bounds.end` is the next append position.
    bounds: Range<u64>,

    /// Earliest data blob modified since the last `commit()` or `sync()`.
    dirty_from_blob: Option<u64>,

    /// Test-only: park [Self::prune] after the data-blob removal, before the offsets prune,
    /// so tests can drop the pending future at that exact point.
    #[cfg(test)]
    halt_before_offsets_prune: bool,

    /// The number of items per blob.
    ///
    /// # Invariant
    ///
    /// This value is immutable after initialization and must remain consistent
    /// across restarts. Changing this value will result in data loss or corruption.
    items_per_blob: NonZeroU64,

    /// Optional compression level when encoding items.
    compression: Option<u8>,

    /// Codec configuration for decoding items.
    codec_config: V::Cfg,

    /// Journal and Reader metrics.
    metrics: Arc<Metrics<E>>,
}

/// A reader over a variable journal.
pub struct Reader<'a, E: Context, V: Codec> {
    /// The journal's data blobs.
    data: Blobs<'a, E::Blob>,

    /// The readable position range `[start, end)`.
    bounds: Range<u64>,

    /// Maps each position to the byte offset one past its frame's end within its data blob.
    offsets: fixed::Reader<'a, E, u64>,

    /// The number of items in each blob.
    items_per_blob: NonZeroU64,

    /// [Codec] configuration for decoding items.
    codec_config: V::Cfg,

    /// Whether items are zstd-compressed.
    compressed: bool,

    /// Journal and Reader metrics.
    metrics: Arc<Metrics<E>>,
}

impl<'a, E: Context, V: CodecShared> Reader<'a, E, V> {
    /// Validate a position to be read: must lie within `bounds`.
    const fn validate_readable(&self, position: u64) -> Result<(), Error> {
        if position >= self.bounds.end {
            return Err(Error::ItemOutOfRange(position));
        }
        if position < self.bounds.start {
            return Err(Error::ItemPruned(position));
        }
        Ok(())
    }

    /// Whether `position` holds the first retained frame of its data blob (starting at byte 0).
    const fn is_first_in_blob(&self, position: u64) -> bool {
        position.is_multiple_of(self.items_per_blob.get()) || position == self.bounds.start
    }

    /// Byte offset where `position`'s frame starts, if resolvable without I/O: the first
    /// retained frame of a blob starts at byte 0, and any other frame starts where its
    /// predecessor's entry says it ends.
    fn frame_start_sync(&self, position: u64) -> Option<u64> {
        if self.is_first_in_blob(position) {
            return Some(0);
        }
        self.offsets.try_read_sync(position - 1)
    }

    /// Byte offset where `position`'s frame starts, reading the predecessor entry if needed.
    async fn frame_start(&self, position: u64) -> Result<u64, Error> {
        if self.is_first_in_blob(position) {
            return Ok(0);
        }
        self.offsets.read(position - 1).await
    }

    /// Read the varint-framed item at byte `offset` via `blob`.
    async fn read_at_offset(&self, blob: &Blob<'_, E::Blob>, offset: u64) -> Result<V, Error> {
        read_frame_at(blob, offset, &self.codec_config, self.compressed)
            .await
            .map(|(_, _, item)| item)
    }

    /// Read consecutive items in one blob. `offsets` must be strictly increasing byte offsets of
    /// byte-adjacent frames.
    ///
    /// Returns [Error::OffsetDataMismatch] if the on-disk varint at any offset reports a size
    /// inconsistent with the gap to the next offset, or [Error::Corruption] if the offsets are not
    /// strictly increasing.
    async fn read_consecutive(
        &self,
        blob_handle: &Blob<'_, E::Blob>,
        blob: u64,
        offsets: &[u64],
    ) -> Result<Vec<V>, Error> {
        // Trivial spans take the single-item path; there is nothing to batch.
        if offsets.len() <= 1 {
            let mut items = Vec::with_capacity(offsets.len());
            for &offset in offsets {
                items.push(self.read_at_offset(blob_handle, offset).await?);
            }
            return Ok(items);
        }

        for window in offsets.windows(2) {
            if window[1] <= window[0] {
                return Err(Error::Corruption(format!(
                    "non-increasing offsets in blob {blob}: {} >= {}",
                    window[0], window[1]
                )));
            }
        }

        // Read the byte span covering every item but the last in one operation; the last item's
        // length is unknown, so it goes through the single-item path.
        let start = offsets[0];
        let end = offsets[offsets.len() - 1];
        let range_len = usize::try_from(end - start).map_err(|_| Error::OffsetOverflow)?;
        let bytes = blob_handle.read_at(start, range_len).await?.coalesce();
        let bytes = bytes.as_ref();

        let mut items = Vec::with_capacity(offsets.len());
        let mut local_offset = 0usize;
        for window in offsets.windows(2) {
            let offset = window[0];
            let next_offset = window[1];
            let item_len =
                usize::try_from(next_offset - offset).map_err(|_| Error::OffsetOverflow)?;

            let mut cursor = Cursor::new(&bytes[local_offset..]);
            let (size, varint_len) = decode_length_prefix(&mut cursor)?;
            let actual_len = size.checked_add(varint_len).ok_or(Error::OffsetOverflow)?;
            if actual_len != item_len {
                return Err(Error::OffsetDataMismatch {
                    section: blob,
                    offset,
                    expected_len: item_len,
                    actual_len,
                });
            }

            // Validation above guarantees strictly increasing offsets, so `data_end` never
            // exceeds `range_len` and these additions stay in bounds.
            let data_start = local_offset
                .checked_add(varint_len)
                .ok_or(Error::OffsetOverflow)?;
            let data_end = local_offset
                .checked_add(item_len)
                .ok_or(Error::OffsetOverflow)?;
            items.push(decode_item::<V>(
                &bytes[data_start..data_end],
                &self.codec_config,
                self.compressed,
            )?);

            local_offset = data_end;
        }

        items.push(self.read_at_offset(blob_handle, end).await?);
        Ok(items)
    }

    /// Read the varint-framed item for `position` at byte `offset` from cached bytes, returning
    /// `None` on any miss.
    fn try_read_frame_sync(&self, position: u64, offset: u64, buf: &mut Vec<u8>) -> Option<V> {
        let blob = self
            .data
            .get(position_to_blob(position, self.items_per_blob.get()))?;
        let remaining = blob.size().checked_sub(offset)?;
        let header_len = usize::try_from(remaining.min(MAX_U32_VARINT_SIZE as u64)).ok()?;
        if header_len == 0 {
            return None;
        }

        // Read the varint header to determine item size.
        let mut header = [0u8; MAX_U32_VARINT_SIZE];
        if !blob.try_read_sync_into(&mut header[..header_len], offset) {
            return None;
        }
        let mut cursor = Cursor::new(&header[..header_len]);
        let (_, item_info) = find_frame(&mut cursor, offset).ok()?;

        let (varint_len, data_len) = match item_info {
            FrameInfo::Complete {
                varint_len,
                data_len,
            } => (varint_len, data_len),
            FrameInfo::Incomplete {
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
        if !blob.try_read_sync_into(buf, offset) {
            return None;
        }
        decode_item::<V>(
            &buf[varint_len..varint_len + data_len],
            &self.codec_config,
            self.compressed,
        )
        .ok()
    }

    /// Build one replay state for each data blob touched by `[start_pos, bounds.end)`.
    async fn replay_states(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<Vec<ReplayState<'a, E::Blob, V>>, Error> {
        let bounds = self.bounds();
        if start_pos > bounds.end {
            return Err(Error::ItemOutOfRange(start_pos));
        }
        if start_pos < bounds.start {
            return Err(Error::ItemPruned(start_pos));
        }

        let mut states = Vec::new();
        if start_pos < bounds.end {
            // The first blob may start at a nonzero data offset; subsequent blob states always
            // start at byte offset 0.
            let items_per_blob = self.items_per_blob.get();
            let start_blob = position_to_blob(start_pos, items_per_blob);
            let end_blob = position_to_blob(bounds.end - 1, items_per_blob);
            let start_offset = self.frame_start(start_pos).await?;

            for blob in start_blob..=end_blob {
                let blob_handle = self
                    .data
                    .get(blob)
                    .expect("positions in bounds map to a retained blob");
                let offset = if blob == start_blob { start_offset } else { 0 };

                let first_pos = if blob == start_blob {
                    start_pos
                } else {
                    blob_first_position(blob, items_per_blob)?
                };
                let end_pos = super::blob_end_position(blob, items_per_blob, bounds.end);

                // Store codec settings in the state because the stream owns states across await
                // points and cannot borrow `self`.
                states.push(ReplayState::<E::Blob, V> {
                    blob,
                    replay: blob_handle.replay_from(offset, buffer)?,
                    budget: buffer.get() as u64,
                    pos: first_pos,
                    end_pos,
                    offset,
                    codec_config: self.codec_config.clone(),
                    compressed: self.compressed,
                    _marker: PhantomData,
                });
            }
        }

        Ok(states)
    }

    /// Validate a batched-read request: non-empty `positions` must be strictly increasing and
    /// fall within `bounds`.
    fn validate_read_many(&self, positions: &[u64]) -> Result<(), Error> {
        if positions[0] < self.bounds.start {
            return Err(Error::ItemPruned(positions[0]));
        }
        let last_position = *positions.last().expect("positions is not empty");
        if last_position >= self.bounds.end {
            return Err(Error::ItemOutOfRange(last_position));
        }
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        Ok(())
    }

    /// Read `miss_positions` from storage and fill their slots in `result`. `miss_offsets[i]`
    /// is the byte offset of `miss_positions[i]`'s frame, and `miss_indices[i]` is the `result`
    /// slot for `miss_positions[i]` (identity when `None`).
    async fn read_misses(
        &self,
        result: &mut [Option<V>],
        miss_indices: Option<&[usize]>,
        miss_positions: &[u64],
        miss_offsets: &[u64],
    ) -> Result<(), Error> {
        // Group runs of consecutive positions that fall into the same blob, then read all runs
        // concurrently.
        let items_per_blob = self.items_per_blob.get();
        let mut runs = Vec::new();
        let mut group_start = 0;
        while group_start < miss_positions.len() {
            let blob = position_to_blob(miss_positions[group_start], items_per_blob);
            let mut group_end = group_start + 1;
            while group_end < miss_positions.len()
                && position_to_blob(miss_positions[group_end], items_per_blob) == blob
            {
                group_end += 1;
            }

            let blob_handle = self
                .data
                .get(blob)
                .expect("positions in bounds map to a retained blob");
            // Consecutive positions are byte-adjacent frames, so each next offset gives the
            // previous frame's encoded length.
            let mut run_start = group_start;
            while run_start < group_end {
                let mut run_end = run_start + 1;
                while run_end < group_end
                    && miss_positions[run_end - 1].checked_add(1) == Some(miss_positions[run_end])
                {
                    run_end += 1;
                }
                runs.push((run_start, run_end, blob, blob_handle.clone()));
                run_start = run_end;
            }
            group_start = group_end;
        }

        let run_items = try_join_all(runs.iter().map(|(run_start, run_end, blob, handle)| {
            self.read_consecutive(handle, *blob, &miss_offsets[*run_start..*run_end])
        }))
        .await?;
        for ((run_start, _, _, _), items) in runs.iter().zip(run_items) {
            for (k, item) in items.into_iter().enumerate() {
                let slot = miss_indices.map_or(run_start + k, |indices| indices[run_start + k]);
                result[slot] = Some(item);
            }
        }

        Ok(())
    }

    /// One synchronous batched pass over `positions`, filling `out[i]` for every frame served
    /// entirely from the page cache. Returns the per-position frame start offsets resolved
    /// along the way: `Some(offset)` whenever the start was resolved synchronously, even if the
    /// data frame itself missed (callers reuse these offsets so the offsets journal is not
    /// consulted twice).
    fn read_many_sync_pass(&self, positions: &[u64], out: &mut [Option<V>]) -> Vec<Option<u64>> {
        let mut resolved: Vec<Option<u64>> = vec![None; positions.len()];
        if positions.is_empty() {
            return resolved;
        }

        // A frame at position p spans [entry(p - 1), entry(p)) within its blob (starting at 0
        // for the first retained frame of a blob), so one batched pass over the offsets journal
        // resolves every queried frame's extent. Positions and their in-blob predecessors
        // interleave into one strictly increasing lookup list.
        let mut lookups: Vec<u64> = Vec::with_capacity(positions.len() * 2);
        for &position in positions {
            if !self.is_first_in_blob(position) && position > 0 {
                let previous = position - 1;
                if lookups.last() != Some(&previous) {
                    lookups.push(previous);
                }
            }
            if lookups.last() != Some(&position) {
                lookups.push(position);
            }
        }
        let offsets = self.offsets.probe_items(&lookups);

        // Split queried frames into known extents (served below by one batched cache read per
        // data blob) and unknown extents (start known but end lookup missed, served by the
        // per-frame path). Frames whose start could not be resolved stay `None`.
        let items_per_blob = self.items_per_blob.get();
        let mut extents: Vec<(usize, u64, usize)> = Vec::with_capacity(positions.len());
        let mut singles: Vec<(usize, u64)> = Vec::new();
        let mut lookup_idx = 0;
        for (idx, &position) in positions.iter().enumerate() {
            while lookups[lookup_idx] != position {
                lookup_idx += 1;
            }
            if self.validate_readable(position).is_err() {
                continue;
            }

            // The predecessor lookup (when needed) sits immediately before the position's own.
            let offset = if self.is_first_in_blob(position) {
                Some(0)
            } else {
                offsets[lookup_idx - 1]
            };
            let Some(offset) = offset else {
                continue;
            };
            resolved[idx] = Some(offset);

            match offsets[lookup_idx] {
                Some(end) if end > offset => extents.push((idx, offset, (end - offset) as usize)),
                _ => singles.push((idx, offset)),
            }
        }

        let mut buf = Vec::new();
        let mut hits = 0u64;

        // Serve known-extent frames: one batched cache read per data blob group.
        let mut group_start = 0;
        while group_start < extents.len() {
            let blob_num = position_to_blob(positions[extents[group_start].0], items_per_blob);
            let mut group_end = group_start + 1;
            while group_end < extents.len()
                && position_to_blob(positions[extents[group_end].0], items_per_blob) == blob_num
            {
                group_end += 1;
            }
            let group = &extents[group_start..group_end];
            group_start = group_end;

            let Some(blob) = self.data.get(blob_num) else {
                continue;
            };
            let ranges: Vec<(u64, usize)> = group
                .iter()
                .map(|&(_, offset, len)| (offset, len))
                .collect();
            let total: usize = ranges.iter().map(|&(_, len)| len).sum();
            buf.resize(total, 0);
            let missed = blob.try_read_ranges_sync_into(&mut buf, &ranges);
            let mut missed = missed.into_iter().peekable();
            let mut local = 0usize;
            for (range_idx, &(idx, _, len)) in group.iter().enumerate() {
                let slot = &buf[local..local + len];
                local += len;
                if missed.peek() == Some(&range_idx) {
                    missed.next();
                    continue;
                }
                if let Some(item) =
                    decode_frame_from_span(slot, len, &self.codec_config, self.compressed)
                {
                    out[idx] = Some(item);
                    hits += 1;
                }
            }
        }

        // Per-frame path for frames whose extent is unknown.
        let mut frame_buf = Vec::new();
        for (idx, offset) in singles {
            if let Some(item) = self.try_read_frame_sync(positions[idx], offset, &mut frame_buf) {
                out[idx] = Some(item);
                hits += 1;
            }
        }
        self.metrics.cache_hits.inc_by(hits);
        self.metrics.items_read.inc_by(hits);
        resolved
    }
}

/// A position the sync pass could not serve, carrying the frame offset the pass resolved from
/// the offsets journal along the way (when it did).
#[derive(Clone, Copy)]
struct Miss {
    position: u64,
    offset: Option<u64>,
}

/// Complete a sync pass's item slots: read `misses` (the positions of the `None` slots, in
/// order) and fill each slot with its item.
async fn complete<E: Context, V: CodecShared>(
    reader: &Reader<'_, E, V>,
    items: Vec<Option<V>>,
    misses: Vec<Miss>,
) -> Result<Vec<V>, Error> {
    if misses.is_empty() {
        return Ok(items
            .into_iter()
            .map(|item| item.expect("complete probe has no misses"))
            .collect());
    }

    let fetched = reader.fetch_misses(&misses).await?;
    let mut fetched = fetched.into_iter();
    Ok(items
        .into_iter()
        .map(|item| item.unwrap_or_else(|| fetched.next().expect("one fetched item per miss")))
        .collect())
}

impl<E: Context, V: CodecShared> Reader<'_, E, V> {
    /// One probe pass over strictly increasing `positions`: one item slot per position plus
    /// the misses, each carrying any frame offset the pass resolved.
    fn probe_parts(&self, positions: &[u64]) -> (Vec<Option<V>>, Vec<Miss>) {
        let mut items: Vec<Option<V>> = (0..positions.len()).map(|_| None).collect();
        let resolved = self.read_many_sync_pass(positions, &mut items);
        let misses = positions
            .iter()
            .zip(&items)
            .zip(resolved)
            .filter_map(|((&position, item), offset)| {
                item.is_none().then_some(Miss { position, offset })
            })
            .collect();
        (items, misses)
    }

    /// Complete probe misses (strictly increasing by position): resolve outstanding frame
    /// starts without the offsets journal's cache pass (those entries just missed it) and read
    /// the frames with one batched pass per blob run. Returns one item per miss, in order.
    async fn fetch_misses(&self, misses: &[Miss]) -> Result<Vec<V>, Error> {
        if misses.is_empty() {
            return Ok(Vec::new());
        }

        // Validate before consulting the offsets journal so a probe-declined out-of-bounds
        // position surfaces as a range error rather than corruption.
        for miss in misses {
            self.validate_readable(miss.position)?;
        }

        // A frame start is its predecessor's entry. First-in-blob positions resolve to zero in
        // the sync pass and are never unresolved here.
        let unresolved: Vec<u64> = misses
            .iter()
            .filter(|miss| miss.offset.is_none())
            .map(|miss| miss.position - 1)
            .collect();

        // Range errors from the offsets journal are corruption: the positions were already
        // validated against `bounds`, so the offsets journal must have them.
        let fetched = self
            .offsets
            .read_many_inner(&unresolved)
            .await
            .map_err(|e| match e {
                Error::ItemOutOfRange(e) | Error::ItemPruned(e) => {
                    Error::Corruption(format!("blob/item should be found, but got: {e}"))
                }
                other => other,
            })?;
        let mut fetched = fetched.into_iter();
        let offsets: Vec<u64> = misses
            .iter()
            .map(|miss| {
                miss.offset.unwrap_or_else(|| {
                    fetched
                        .next()
                        .expect("one fetched offset per unresolved miss")
                })
            })
            .collect();
        let positions: Vec<u64> = misses.iter().map(|miss| miss.position).collect();

        let mut result: Vec<Option<V>> = (0..misses.len()).map(|_| None).collect();
        self.read_misses(&mut result, None, &positions, &offsets)
            .await?;
        self.metrics.cache_misses.inc_by(positions.len() as u64);
        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result
            .into_iter()
            .map(|item| item.expect("read_misses fills every slot"))
            .collect())
    }
}

impl<E: Context, V: CodecShared> super::Contiguous for Reader<'_, E, V> {
    type Item = V;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<V, Error> {
        self.metrics.read_calls.inc();
        self.validate_readable(position)?;

        // Resolve the frame start synchronously when possible. On a data-frame miss the
        // resolved offset is reused by the async path so the offsets journal is not consulted
        // twice.
        let cached_offset = self.frame_start_sync(position);
        if let Some(offset) = cached_offset {
            let mut buf = Vec::new();
            if let Some(item) = self.try_read_frame_sync(position, offset, &mut buf) {
                self.metrics.cache_hits.inc();
                self.metrics.items_read.inc();
                return Ok(item);
            }
        }

        let _timer = self.metrics.read_timer();
        let offset = match cached_offset {
            Some(offset) => offset,
            None => self.frame_start(position).await?,
        };
        let blob = self
            .data
            .get(position_to_blob(position, self.items_per_blob.get()))
            .expect("position in bounds maps to a retained blob");
        self.metrics.cache_misses.inc();
        let item = self.read_at_offset(&blob, offset).await?;
        self.metrics.items_read.inc();
        Ok(item)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<V>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let _timer = self.metrics.read_many_timer();
        self.metrics.read_many_calls.inc();
        self.validate_read_many(positions)?;
        let (items, misses) = self.probe_parts(positions);
        complete(self, items, misses).await
    }

    fn try_read_sync(&self, position: u64) -> Option<V> {
        self.validate_readable(position).ok()?;
        let offset = self.frame_start_sync(position)?;
        let mut buf = Vec::new();
        let item = self.try_read_frame_sync(position, offset, &mut buf)?;
        self.metrics.cache_hits.inc();
        self.metrics.items_read.inc();
        Some(item)
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<V>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let mut items: Vec<Option<V>> = (0..positions.len()).map(|_| None).collect();
        self.read_many_sync_pass(positions, &mut items);
        items
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + Send, Error> {
        let states = self.replay_states(start_pos, buffer).await?;

        Ok(super::replay_stream_from_states(states))
    }
}

impl<E: Context, V: CodecShared> Journal<E, V> {
    /// Mark all data blobs from `blob` onward as dirty.
    fn mark_dirty_from(&mut self, blob: u64) {
        self.dirty_from_blob = Some(
            self.dirty_from_blob
                .map_or(blob, |existing| existing.min(blob)),
        );
    }

    /// Initialize a contiguous variable journal.
    ///
    /// # Crash Recovery
    ///
    /// If a crash left the offsets journal and data blobs at different durable frontiers, init
    /// reconciles them with bounded repairs (see the type docs).
    #[boxed]
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let items_per_blob = cfg.items_per_section.get();
        let data_partition = cfg.data_partition();
        let data_context = context.child("data");

        let mut offsets = fixed::Journal::<E, u64>::init(
            context.child("offsets"),
            fixed::Config {
                partition: cfg.offsets_partition(),
                items_per_blob: cfg.items_per_section,
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        let partition = Partition::new(
            data_context,
            data_partition,
            cfg.page_cache,
            cfg.write_buffer,
        );
        let mut pending = partition.open_all().await?;

        // Validate and align the offsets journal against the data blobs.
        let bounds = Self::align(&partition, &mut pending, &mut offsets, items_per_blob).await?;

        // Seal every blob below the tail and assemble the blobs.
        let tail_blob = position_to_blob(bounds.end, items_per_blob);
        let blobs = Writable::recover(partition, pending, tail_blob).await?;

        let metrics = Metrics::new(context);
        metrics.update(bounds.end, bounds.start, items_per_blob);

        Ok(Self {
            blobs,
            offsets,
            bounds,
            dirty_from_blob: None,
            #[cfg(test)]
            halt_before_offsets_prune: false,
            items_per_blob: cfg.items_per_section,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            metrics: Arc::new(metrics),
        })
    }

    /// Initialize an empty [Journal] at the given logical `size`.
    ///
    /// This discards any existing data and offsets: the data partition removal, the offsets
    /// blob removals, and the offsets boundary record land in ONE batch, so on atomic backends
    /// the reset is old-state-or-new-state.
    ///
    /// Returns a journal with journal.bounds() == Range{start: size, end: size}
    /// and next append at position `size`.
    #[commonware_macros::stability(ALPHA)]
    pub async fn init_at_size(context: E, cfg: Config<V::Cfg>, size: u64) -> Result<Self, Error> {
        // A journal sized at `u64::MAX` can never accept an append, matching the fixed journal.
        if size == u64::MAX {
            return Err(Error::SizeOverflow);
        }
        let data_partition = cfg.data_partition();
        let data_context = context.child("data");
        let offsets_partition = cfg.offsets_partition();
        let offsets_context = context.child("offsets");

        // Fail before mutating if the offsets blob partitions are already inconsistent.
        Partition::select(&offsets_context, &offsets_partition).await?;

        // One batch resets everything; `init` then recovers the cleared journal.
        let mut checkpoint =
            super::checkpoint::Checkpoint::open(offsets_context.child("meta"), &offsets_partition)
                .await?;
        let mut batch = context.batch().await.map_err(Error::Runtime)?;
        fixed::Journal::<E, u64>::stage_reset(
            &offsets_context,
            &offsets_partition,
            &mut checkpoint,
            size,
            &mut batch,
        )
        .await?;
        match data_context.scan(&data_partition).await {
            Ok(_) => batch.remove(&data_partition, None),
            Err(commonware_runtime::Error::PartitionMissing(_)) => {}
            Err(err) => return Err(Error::Runtime(err)),
        }
        batch.apply_sync().await.map_err(Error::Runtime)?;
        drop(checkpoint);

        Self::init(context, cfg).await
    }

    /// Initialize a [Journal] for use in state sync.
    ///
    /// The bounds are item locations (not blob indexes). This function prepares the
    /// on-disk journal so that subsequent appends go to the correct physical location for the
    /// requested range.
    ///
    /// Behavior by existing on-disk state:
    /// - Fresh (no data): returns an empty journal, resetting to `range.start` if needed.
    /// - Stale (all data strictly before `range.start`): resets to `range.start` using the
    ///   crash-safe clear path and returns an empty journal.
    /// - Overlap within [`range.start`, `range.end`]:
    ///   - Prunes toward `range.start` (blob-aligned, so some items before
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
            items_per_blob = cfg.items_per_section.get(),
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

        // After a same-blob crash during a previous clear_to_size, the journal may recover to a
        // stale position ahead of the requested start.
        let bounds = journal.bounds.clone();
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
    /// # Durability
    ///
    /// Unlike appends, a rewind is durable when this call returns. Appends sync at every blob
    /// rollover, so if the truncations were deferred to `commit`/`sync`, a rollover after the
    /// rewind could durably publish new entries over old data bytes (or vice versa) — a state
    /// init cannot tell apart from a consistent one. Making both truncations durable here keeps
    /// every crash state reconcilable from sizes alone.
    ///
    /// # Errors
    ///
    /// Returns [Error::InvalidRewind] if `size` is larger than current size.
    /// Returns [Error::ItemPruned] if `size` is smaller than the pruning boundary.
    ///
    /// # Warning
    ///
    /// - Readers returned by [`snapshot`](Self::snapshot) may observe unspecified contents if this
    ///   rewind truncates into their range.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.bounds.end) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        // Rewind never updates the pruning boundary.
        if size < self.bounds.start {
            return Err(Error::ItemPruned(size));
        }

        let discard_blob = position_to_blob(size, self.items_per_blob.get());

        // The byte offset of the first discarded item is the data truncation point.
        let discard_offset =
            if size.is_multiple_of(self.items_per_blob.get()) || size == self.bounds.start {
                0
            } else {
                self.offsets.read(size - 1).await?
            };

        // Durably rewind the offsets journal first: if the data truncation lands without it, the
        // surviving entries still describe the surviving data prefix, which init reconciles.
        self.offsets.rewind(size).await?;
        self.offsets.commit().await?;

        if discard_blob == self.blobs.tail_blob_index() {
            self.blobs.rewind_tail(discard_offset).await?;
        } else {
            self.blobs
                .rewind_into_sealed(discard_blob, discard_offset)
                .await?;
        }

        // Make the data truncation durable before returning (see Durability above).
        self.mark_dirty_from(discard_blob);
        self.flush_dirty_data().await?;
        self.dirty_from_blob = None;

        self.bounds.end = size;
        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );

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
            encode_frame_into(self.compression, item, &mut encoded)
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
            compressed: self.compression.is_some(),
            _marker: PhantomData,
        })
    }

    /// Append items encoded by [`Self::prepare_append`], returning the position of the last item
    /// appended.
    ///
    /// Returns [Error::EmptyAppend] if `prepared` contains no items.
    /// Returns [Error::InvalidConfiguration] if `prepared` was encoded with different compression
    /// settings than this journal uses.
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
            compressed,
            ..
        } = prepared;
        let items_count = item_starts.len();
        if items_count == 0 {
            return Err(Error::EmptyAppend);
        }
        if compressed != self.compression.is_some() {
            return Err(Error::InvalidConfiguration(
                "prepared append compression setting does not match journal".into(),
            ));
        }
        let encoded = IoBuf::from(encoded);

        // Reject the append before writing anything (to either the data blobs or offsets
        // journal) if it would push the size past `u64::MAX`.
        self.bounds
            .end
            .checked_add(items_count as u64)
            .ok_or(Error::SizeOverflow)?;

        let items_per_blob = self.items_per_blob.get();
        self.mark_dirty_from(position_to_blob(self.bounds.end, items_per_blob));
        let mut written = 0;
        while written < items_count {
            let batch_count = super::batch_count_to_blob_boundary(
                self.bounds.end,
                items_count - written,
                items_per_blob,
            );
            let batch_start = item_starts[written];
            let batch_end = item_starts
                .get(written + batch_count)
                .copied()
                .unwrap_or(encoded.len());

            // Append pre-encoded data to the tail, then convert relative item boundaries into
            // absolute frame end offsets. A large batch is written whole-page-direct to the
            // blob; the returned offset is where this batch's first byte was written.
            let base_offset = self
                .blobs
                .tail_writer()
                .append_owned(encoded.slice(batch_start..batch_end))
                .await
                .map_err(Error::Runtime)?;

            let absolute_ends = (0..batch_count)
                .map(|item| {
                    let end = item_starts
                        .get(written + item + 1)
                        .copied()
                        .unwrap_or(encoded.len());
                    base_offset
                        .checked_add((end - batch_start) as u64)
                        .ok_or(Error::OffsetOverflow)
                })
                .collect::<Result<Vec<u64>, _>>()?;

            // Append the frame ends for this blob batch to the offsets journal.
            let last_offsets_pos = self.offsets.append_many(Many::Flat(&absolute_ends)).await?;
            assert_eq!(last_offsets_pos, self.bounds.end + batch_count as u64 - 1);

            self.bounds.end += batch_count as u64;
            written += batch_count;

            // Seal the just-filled tail (fsyncing it) and open the next blob as the new tail.
            // Every data blob below the new tail is now durable, so dirty tracking restarts
            // there.
            if self.bounds.end.is_multiple_of(items_per_blob) {
                self.blobs.seal_tail().await?;
                self.dirty_from_blob = Some(self.blobs.tail_blob_index());
            }
        }

        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );
        Ok(self.bounds.end - 1)
    }

    /// Capture an owned snapshot ([`Reader`]) over the current journal. Bounds are frozen at
    /// creation, and the snapshot stays readable across concurrent appends and prunes.
    ///
    /// If the journal later rewinds into the returned reader's range, subsequent reads
    /// from that range may observe unspecified contents.
    pub async fn snapshot(&mut self) -> Result<Reader<'static, E, V>, Error> {
        Ok(Reader {
            data: self.blobs.snapshot().await?,
            bounds: self.bounds.clone(),
            offsets: self.offsets.snapshot().await?,
            items_per_blob: self.items_per_blob,
            codec_config: self.codec_config.clone(),
            compressed: self.compression.is_some(),
            metrics: self.metrics.clone(),
        })
    }

    /// A reader borrowing the journal's live state.
    fn reader(&self) -> Reader<'_, E, V> {
        Reader {
            data: self.blobs.reader(),
            bounds: self.bounds.clone(),
            offsets: self.offsets.reader(),
            items_per_blob: self.items_per_blob,
            codec_config: self.codec_config.clone(),
            compressed: self.compression.is_some(),
            metrics: self.metrics.clone(),
        }
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub const fn size(&self) -> u64 {
        self.bounds.end
    }

    /// Prune items at positions strictly less than `min_position`.
    ///
    /// Returns `true` if any data was pruned, `false` otherwise.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        let items_per_blob = self.items_per_blob.get();

        // Calculate the blob that would contain min_position, capped to the tail (which is
        // guaranteed to exist by our invariant).
        let target_blob = position_to_blob(min_position, items_per_blob);
        let tail_blob = position_to_blob(self.bounds.end, items_per_blob);
        let min_blob = target_blob.min(tail_blob);

        if min_blob <= self.blobs.oldest_blob_index() {
            return Ok(false);
        }

        let new_boundary = blob_first_position(min_blob, items_per_blob)?;

        // Make all dirty state durable before removing any blob: the prune target may be
        // justified by an appended-but-unflushed item (e.g. a consumer's commit record), and
        // removals are durable, so pruning without this barrier could leave a recovered
        // journal whose surviving items no longer justify its boundary. Offsets entries for
        // retained items must survive the same crash: init treats offsets ending behind the
        // oldest retained data as corruption because the data needed to reconstruct the
        // missing entries is about to be removed. One batch stages data before offsets,
        // matching the ordering every other durability path maintains on the fallback.
        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        self.commit_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)?;

        self.blobs.prune(min_blob).await?;
        self.bounds.start = new_boundary;

        #[cfg(test)]
        if self.halt_before_offsets_prune {
            std::future::pending::<()>().await;
        }

        // Prune data before offsets so a crash leaves offsets behind, which init repairs by
        // pruning offsets to match.
        self.offsets.prune(new_boundary).await?;
        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );

        Ok(true)
    }

    /// Make dirty data blobs durable.
    async fn flush_dirty_data(&mut self) -> Result<(), Error> {
        let Some(start_blob) = self.dirty_from_blob else {
            return Ok(());
        };
        self.blobs.sync_from(start_blob).await
    }

    /// Stage the durability of dirty data blobs and the offsets journal
    /// with `batch`. Data is staged before offsets: the sequential fallback
    /// syncs in staging order, preserving the data-then-offsets ordering
    /// that keeps durable offsets at or behind durable data (which init
    /// repairs by truncating the unindexed data suffix). On the volume the
    /// whole batch commits atomically and no crash can separate them.
    async fn commit_into(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        if let Some(start_blob) = self.dirty_from_blob {
            self.blobs.sync_from_into(start_blob, batch).await?;
            self.dirty_from_blob = None;
        }
        self.offsets.commit_into(batch).await
    }

    /// Durably persist the journal: dirty data blobs and the offsets
    /// journal, one batch, one commit on atomic backends.
    pub async fn commit(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.commit_timer();
        self.metrics.commit_calls.inc();
        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        self.commit_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// Like [Self::commit], but also persists the offsets journal's checkpoint (in the same
    /// batch).
    pub async fn sync(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        if let Some(start_blob) = self.dirty_from_blob {
            self.blobs.sync_from_into(start_blob, &mut batch).await?;
            self.dirty_from_blob = None;
        }
        self.offsets.sync_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// Remove any underlying blobs created by the journal.
    ///
    /// This destroys both the data blobs and the offsets journal.
    ///
    /// # Crash Safety
    ///
    /// This operation is intended for final teardown and is not crash-safe. If interrupted,
    /// reopening the same partitions may observe partially removed state. Use [Self::init_at_size]
    /// for a recoverable reset.
    pub async fn destroy(self) -> Result<(), Error> {
        self.blobs.destroy().await?;
        self.offsets.destroy().await
    }

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused.
    /// After clearing, the journal will behave as if initialized with `init_at_size(new_size)`.
    /// The data blob removals, the offsets blob removals, and the offsets boundary record land
    /// in ONE batch, so on atomic backends a crash leaves the journal either in its prior
    /// state or fully cleared.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn clear_to_size(&mut self, new_size: u64) -> Result<(), Error> {
        // A journal sized at `u64::MAX` can never accept an append, matching `init_at_size`.
        if new_size == u64::MAX {
            return Err(Error::SizeOverflow);
        }

        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        self.blobs.stage_clear(&mut batch);
        self.offsets.stage_clear(new_size, &mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)?;

        self.blobs
            .finish_clear(position_to_blob(new_size, self.items_per_blob.get()))
            .await?;
        self.offsets.finish_clear(new_size).await?;
        self.bounds = new_size..new_size;
        self.dirty_from_blob = None;
        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );
        Ok(())
    }

    /// Reconcile the offsets journal and data blobs after a crash left them at different
    /// durable frontiers. Repairs mutate `pending` in place. Blob-index contiguity is enforced
    /// by [Writable::recover].
    ///
    /// Every mutation orders its syncs so the durable offsets entries and durable data bytes
    /// describe prefixes of one shared history (see the type docs), so reconciliation is a
    /// bounded comparison of sizes: no frame is ever scanned or decoded.
    ///
    /// On the volume backend the tail repair is unreachable: data and offsets commit in ONE
    /// batch, so their durable frontiers can never diverge. It is kept for per-blob backends
    /// (MemStorage and the sequential batch fallback), whose apply syncs data before offsets
    /// and can crash between the two.
    ///
    /// Returns the recovered bounds (`pruning_boundary..size`).
    async fn align(
        partition: &Partition<E>,
        pending: &mut BTreeMap<u64, Writer<E::Blob>>,
        offsets: &mut fixed::Journal<E, u64>,
        items_per_blob: u64,
    ) -> Result<Range<u64>, Error> {
        let offsets_bounds = offsets.pruning_boundary()..offsets.size();

        // With no data blobs the offsets journal must be empty: entries become durable only
        // after the data blob they describe exists, and the only path that removes every
        // retained data blob (a clear) rewinds the offsets journal in the same batch.
        let Some(&oldest_blob) = pending.keys().next() else {
            if !offsets_bounds.is_empty() {
                return Err(Error::Corruption(format!(
                    "offsets journal has entries {}..{} but no data blobs exist",
                    offsets_bounds.start, offsets_bounds.end
                )));
            }
            let size = offsets_bounds.end;
            return Ok(size..size);
        };

        // Head repair: a crash between prune's data-blob removals and its offsets prune leaves
        // offsets starting behind the oldest data blob, so prune them forward to match. Offsets
        // ending behind the oldest data blob, or starting in a later blob than the data, cannot
        // arise from the maintained orderings and are corruption.
        let data_oldest_pos = blob_first_position(oldest_blob, items_per_blob)?;
        if offsets_bounds.end < data_oldest_pos {
            return Err(Error::Corruption(format!(
                "offsets journal size {} is behind data oldest position {data_oldest_pos}",
                offsets_bounds.end
            )));
        }
        let offsets_start_blob = position_to_blob(offsets_bounds.start, items_per_blob);
        match offsets_start_blob.cmp(&oldest_blob) {
            std::cmp::Ordering::Less => {
                warn!("crash repair: pruning offsets journal to {data_oldest_pos}");
                offsets.prune(data_oldest_pos).await?;
            }
            std::cmp::Ordering::Equal => {}
            std::cmp::Ordering::Greater => {
                return Err(Error::Corruption(format!(
                    "offsets start blob {offsets_start_blob} ahead of \
                     oldest data blob {oldest_blob}"
                )));
            }
        }

        // Re-fetch bounds since prune may have been called above.
        let offsets_bounds = offsets.pruning_boundary()..offsets.size();

        // Tail repair: find the largest position whose entry the durable data backs, rewind the
        // offsets there, and truncate unindexed data past it. `last_indexed` carries the blob
        // holding the last backed entry and the byte length that entry vouches for.
        let (target, last_indexed) = if offsets_bounds.is_empty() {
            (offsets_bounds.end, None)
        } else {
            // Entries land in the offsets journal before the data blob holding the NEXT blob's
            // frames is created, so only the last indexed blob can disagree with its entries;
            // older blobs are verified below.
            let last_blob = position_to_blob(offsets_bounds.end - 1, items_per_blob);
            let base = first_position_in_blob(offsets_bounds.start, last_blob, items_per_blob)?;
            let data_size = pending.get(&last_blob).map_or(0, |writer| writer.size());

            // One batched read serves both the verification of every older blob's byte length
            // (against its last entry) and the last blob's entries for the binary search.
            let mut positions = Vec::new();
            for &blob in pending.keys() {
                if blob >= last_blob {
                    break;
                }
                let last_position = blob_first_position(blob + 1, items_per_blob)? - 1;
                positions.push(last_position);
            }
            let older = positions.len();
            positions.extend(base..offsets_bounds.end);
            let entries = offsets.reader().read_many_inner(&positions).await?;

            for (idx, &blob) in pending.keys().take_while(|&&b| b < last_blob).enumerate() {
                let expected = entries[idx];
                let actual = pending.get(&blob).map_or(0, |writer| writer.size());
                if actual != expected {
                    return Err(Error::Corruption(format!(
                        "data blob {blob} holds {actual} bytes but its entries end at {expected}"
                    )));
                }
            }

            // Entries within a blob are strictly increasing frame ends.
            let entries = &entries[older..];
            let mut previous = 0;
            for &entry in entries {
                if entry <= previous {
                    return Err(Error::Corruption(format!(
                        "offsets entries are not increasing: {entry} after {previous}"
                    )));
                }
                previous = entry;
            }

            let backed = entries.partition_point(|&end| end <= data_size);
            if backed == 0 {
                (base, None)
            } else {
                (base + backed as u64, Some((last_blob, entries[backed - 1])))
            }
        };

        // Discard entries the durable data does not back. Uncommitted appends vanish with the
        // crash, so this only drops entries whose frames were never durably written.
        if offsets_bounds.end > target {
            warn!(
                from = offsets_bounds.end,
                to = target,
                "crash repair: rewinding offsets to durable data"
            );
            offsets.rewind(target).await?;
            offsets.commit().await?;
        }

        // Remove data blobs past the recovered tail, then truncate unindexed bytes: the last
        // indexed blob down to its last backed entry, and a trailing (unindexed) tail blob to
        // empty.
        let tail_blob = position_to_blob(target, items_per_blob);
        Self::remove_blobs_after(partition, pending, tail_blob).await?;
        match last_indexed {
            Some((blob, backed_size)) => {
                Self::truncate_blob(pending, blob, backed_size).await?;
                if tail_blob > blob {
                    Self::truncate_blob(pending, tail_blob, 0).await?;
                }
            }
            None => Self::truncate_blob(pending, tail_blob, 0).await?,
        }

        Ok(offsets_bounds.start..target)
    }

    /// Truncate `blob` (if present) to `size` bytes and make the truncation durable.
    async fn truncate_blob(
        pending: &mut BTreeMap<u64, Writer<E::Blob>>,
        blob: u64,
        size: u64,
    ) -> Result<(), Error> {
        let Some(writer) = pending.get_mut(&blob) else {
            return Ok(());
        };
        if writer.size() > size {
            warn!(blob, new_size = size, "crash repair: truncating data blob");
            writer.resize(size).await.map_err(Error::Runtime)?;
            writer.sync().await.map_err(Error::Runtime)?;
        }
        Ok(())
    }

    /// Remove every blob newer than `blob`, newest-first so a crash leaves a contiguous prefix.
    async fn remove_blobs_after(
        partition: &Partition<E>,
        pending: &mut BTreeMap<u64, Writer<E::Blob>>,
        blob: u64,
    ) -> Result<(), Error> {
        while let Some((&newest, _)) = pending.last_key_value() {
            if newest <= blob {
                break;
            }
            drop(pending.remove(&newest));
            partition.remove(newest).await?;
        }
        Ok(())
    }
}

impl<E: Context, V: CodecShared> Contiguous for Journal<E, V> {
    type Item = V;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, position: u64) -> Result<V, Error> {
        self.reader().read(position).await
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<V>, Error> {
        self.reader().read_many(positions).await
    }

    fn try_read_sync(&self, position: u64) -> Option<V> {
        self.reader().try_read_sync(position)
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<V>> {
        self.reader().try_read_many_sync(positions)
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, V), Error>> + Send, Error> {
        let reader = self.reader();
        let states = reader.replay_states(start_pos, buffer).await?;

        Ok(super::replay_stream_from_states(states))
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
impl<E: Context, V: CodecShared> authenticated::Inner<E> for Journal<E, V> {
    type Config = Config<V::Cfg>;

    async fn init<
        F: merkle::Family,
        H: commonware_cryptography::Hasher,
        S: commonware_parallel::Strategy,
    >(
        context: E,
        merkle_cfg: merkle::full::Config<S>,
        journal_cfg: Self::Config,
        rewind_predicate: fn(&V) -> bool,
        bagging: merkle::Bagging,
    ) -> Result<authenticated::Journal<F, E, Self, H, S>, authenticated::Error<F>> {
        authenticated::Journal::<F, E, Self, H, S>::new(
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
    /// Test helper: Prune the data blobs directly (simulates crash scenario).
    pub(crate) async fn test_prune_data(&mut self, min_blob: u64) -> Result<bool, Error> {
        let min_blob = min_blob.min(self.blobs.tail_blob_index());
        if min_blob <= self.blobs.oldest_blob_index() {
            return Ok(false);
        }
        self.blobs.prune(min_blob).await?;
        Ok(true)
    }

    /// Test helper: Prune the internal offsets journal directly (simulates crash scenario).
    pub(crate) async fn test_prune_offsets(&mut self, position: u64) -> Result<bool, Error> {
        self.offsets.prune(position).await
    }

    /// Test helper: Durably rewind the internal offsets journal (simulates crash scenario).
    pub(crate) async fn test_rewind_offsets(&mut self, position: u64) -> Result<(), Error> {
        self.offsets.rewind(position).await?;
        self.offsets.commit().await
    }

    /// Test helper: Get the size of the internal offsets journal.
    pub(crate) fn test_offsets_size(&self) -> u64 {
        self.offsets.size()
    }

    /// Test helper: Rewind the data blobs to the item at `position` (simulates crash scenario).
    pub(crate) async fn test_rewind_data_to_position(
        &mut self,
        position: u64,
    ) -> Result<(), Error> {
        let items_per_blob = self.items_per_blob.get();
        let offset = if position.is_multiple_of(items_per_blob) || position == self.bounds.start {
            0
        } else {
            self.offsets.read(position - 1).await?
        };
        let blob = position_to_blob(position, items_per_blob);
        if blob == self.blobs.tail_blob_index() {
            self.blobs.rewind_tail(offset).await
        } else {
            self.blobs.rewind_into_sealed(blob, offset).await
        }
    }

    /// Test helper: Append directly to the data blobs without indexing (simulates crash
    /// scenario). The target must be the tail blob or a newer one (created as an orphan).
    pub(crate) async fn test_append_data(
        &mut self,
        blob: u64,
        item: V,
    ) -> Result<(u64, u32), Error> {
        let mut encoded = Vec::new();
        encode_frame_into(self.compression, &item, &mut encoded)?;
        let item_len = encoded.len() as u32;

        let tail_blob = self.blobs.tail_blob_index();
        if blob == tail_blob {
            let writer = self.blobs.tail_writer();
            let offset = writer.size();
            writer.append(&encoded).await.map_err(Error::Runtime)?;
            return Ok((offset, item_len));
        }
        assert!(blob > tail_blob, "cannot append to a sealed blob");
        let mut writer = self.blobs.open_blob(blob).await?;
        let offset = writer.size();
        writer.append(&encoded).await.map_err(Error::Runtime)?;
        writer.sync().await.map_err(Error::Runtime)?;
        Ok((offset, item_len))
    }

    /// Test helper: Sync the data tail.
    pub(crate) async fn test_sync_data(&mut self) -> Result<(), Error> {
        self.blobs.sync_from(self.blobs.tail_blob_index()).await
    }

    /// Test helper: Sync one data blob.
    pub(crate) async fn test_sync_data_blob(&mut self, blob: u64) -> Result<(), Error> {
        self.blobs.sync_blob(blob).await
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::tests::run_contiguous_tests;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::{CacheRef, Writer},
        deterministic, Metrics as _, Runner, Spawner as _, Storage, Supervisor as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16, NZU64};
    use futures::{FutureExt as _, StreamExt as _};
    use std::num::NonZeroU16;

    // Use some jank sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    const PAGE_CACHE_SIZE: usize = 2;
    // Larger page sizes for tests that need more buffer space.
    const LARGE_PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const SMALL_PAGE_SIZE: NonZeroU16 = NZU16!(512);

    /// Extract a metric counter's value from encoded metrics output.
    fn counter(buffer: &str, name: &str) -> u64 {
        buffer
            .lines()
            .find(|l| l.contains(name) && !l.starts_with('#'))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .expect("counter missing")
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
    fn test_variable_append_many_exceeding_write_buffer_reopens_across_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "append-many-exceeds-buffer".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(512),
            };
            let items = (0..13)
                .map(|i| FixedBytes::new([i as u8; 300]))
                .collect::<Vec<_>>();

            let mut journal =
                Journal::<_, FixedBytes<300>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(journal.append_many(Many::Flat(&items)).await.unwrap(), 12);
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, FixedBytes<300>>::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..13);
            for (pos, item) in items.iter().enumerate() {
                assert_eq!(journal.read(pos as u64).await.unwrap(), *item);
            }
            assert_eq!(
                journal.read_many(&[0, 4, 5, 9, 10, 12]).await.unwrap(),
                vec![
                    items[0].clone(),
                    items[4].clone(),
                    items[5].clone(),
                    items[9].clone(),
                    items[10].clone(),
                    items[12].clone(),
                ]
            );

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
    fn test_variable_replay_near_max_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "replay-near-max-size".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("near_max"), cfg, u64::MAX - 1)
                    .await
                    .unwrap();
            assert_eq!(journal.append(&7).await.unwrap(), u64::MAX - 1);

            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(u64::MAX - 1, NZUsize!(20)).await.unwrap();
                futures::pin_mut!(stream);
                let (pos, item) = stream.next().await.unwrap().unwrap();
                assert_eq!(pos, u64::MAX - 1);
                assert_eq!(item, 7);
                assert!(stream.next().await.is_none());
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_try_read_many_sync_matches_read_many() {
        // Cached positions are served synchronously and match the async batched read.
        // Positions that fail validation are misses rather than errors.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-sync".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(64)),
                write_buffer: NZUsize!(1024),
            };
            let items = (0..13)
                .map(|i| FixedBytes::new([i as u8; 300]))
                .collect::<Vec<_>>();
            let mut journal = Journal::<_, FixedBytes<300>>::init(context.child("j"), cfg)
                .await
                .unwrap();
            journal.append_many(Many::Flat(&items)).await.unwrap();
            journal.sync().await.unwrap();

            let positions: Vec<u64> = (0..items.len() as u64).collect();
            let reader = journal.snapshot().await.unwrap();
            // Warm both the offsets and data page caches, then expect every position to be
            // served synchronously.
            let expected = reader.read_many(&positions).await.unwrap();
            let served = reader.try_read_many_sync(&positions);
            assert_eq!(served.len(), positions.len());
            for (item, expected) in served.iter().zip(&expected) {
                assert_eq!(item.as_ref().expect("cached position is served"), expected);
            }

            // An out-of-range position is a miss, not an error. Positions grouped with it
            // (same offsets blob) are unaffected: validation trims the out-of-range suffix
            // instead of poisoning the group.
            let served = reader.try_read_many_sync(&[9, 13]);
            assert!(served[0].is_some());
            assert!(served[1].is_none());
            drop(served);
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    #[should_panic(expected = "positions must be strictly increasing")]
    fn test_variable_read_many_rejects_unsorted_positions() {
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

            let reader = journal.snapshot().await.unwrap();
            let _ = reader.read_many(&[2, 1]).await;
        });
    }

    #[test_traced]
    #[should_panic(expected = "positions must be strictly increasing")]
    fn test_variable_read_many_rejects_duplicate_positions() {
        // Duplicates are not strictly increasing either.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-duplicate".into(),
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

            let reader = journal.snapshot().await.unwrap();
            let _ = reader.read_many(&[1, 1]).await;
        });
    }

    #[test_traced]
    fn test_variable_probe_then_read_many_matches_read_many() {
        // A probe completed by one batched read over its declined positions returns the same
        // items as read_many, cold and warm.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-probe-complete".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..12u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let positions: Vec<u64> = (0..12).collect();
            let expected: Vec<u64> = (0..12).map(|i| i * 100).collect();
            let reader = journal.snapshot().await.unwrap();
            for _ in 0..2 {
                let mut served = reader.try_read_many_sync(&positions);
                let misses: Vec<u64> = positions
                    .iter()
                    .zip(&served)
                    .filter_map(|(&pos, item)| item.is_none().then_some(pos))
                    .collect();
                let mut fetched = reader.read_many(&misses).await.unwrap().into_iter();
                for item in served.iter_mut().filter(|item| item.is_none()) {
                    *item = fetched.next();
                }
                let completed: Vec<_> = served.into_iter().map(Option::unwrap).collect();
                assert_eq!(completed, expected);
            }
            assert_eq!(reader.read_many(&positions).await.unwrap(), expected);
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_read_many_reuses_probed_offset() {
        // read_many's sync pass resolves frame offsets even when the frame itself misses. The
        // completion must reuse them instead of consulting the offsets journal again.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Sections of 128 make section 0's offsets exactly fill two flushed pages, so a
            // section-0 offset lookup can genuinely miss (a sealed blob serves a partial
            // trailing page from memory, never the page cache).
            let cfg = Config {
                partition: "read-many-offset-reuse".into(),
                items_per_section: NZU64!(128),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(4)),
                write_buffer: NZUsize!(1024),
            };
            let appended = (0..140)
                .map(|i| FixedBytes::new([i as u8; 300]))
                .collect::<Vec<_>>();
            let mut journal = Journal::<_, FixedBytes<300>>::init(context.child("j"), cfg)
                .await
                .unwrap();
            journal.append_many(Many::Flat(&appended)).await.unwrap();
            journal.sync().await.unwrap();
            let reader = journal.snapshot().await.unwrap();

            // Churn the 4-page pool with section-1 frames (five data pages) so every
            // section-0 page is evicted, then warm the offsets page shared by positions
            // 0..64 without touching position 0's frame page (302-byte frames put frame 0
            // in page 0 and frame 4 in page 2).
            reader
                .read_many(&(128..136).collect::<Vec<u64>>())
                .await
                .unwrap();
            reader.read(4).await.unwrap();

            // The sync pass resolves position 0's offset but cannot serve its frame.
            let (items, misses) = reader.probe_parts(&[0]);
            assert!(items[0].is_none());
            assert_eq!(misses[0].offset, Some(0));

            // read_many consults the offsets journal only in its sync pass, and only for
            // position 0's own entry (the frame start is 0 because position 0 opens its blob).
            // Completion reuses the carried start rather than resolving it again.
            let before = context.encode();
            assert_eq!(
                reader.read_many(&[0]).await.unwrap(),
                vec![appended[0].clone()]
            );
            let after = context.encode();
            assert_eq!(
                counter(&after, "offsets_items_read_total"),
                counter(&before, "offsets_items_read_total") + 1
            );
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
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.snapshot().await.unwrap();
            let positions: Vec<u64> = (3..10).collect();
            let items = reader.read_many(&positions).await.unwrap();
            assert_eq!(items, vec![300, 400, 500, 600, 700, 800, 900]);
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_read_many_scattered_single_runs_across_blobs() {
        // Read a batch where cache hits are interleaved with non-consecutive misses spanning
        // several blobs. The misses split into many small runs that are fetched separately, and
        // each run's items must land in the correct result slots between the cached items. Every
        // item's payload encodes its position, so a wrong run boundary or a misplaced result
        // fails the value assertions.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "read-many-scattered-runs".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(16)),
                write_buffer: NZUsize!(1024),
            };

            // Each item's frame is 302 bytes, so a 5-item blob spans two full 512-byte pages plus
            // a partial page. Full pages are served through the page cache and go cold on reopen,
            // which is what lets this test stage misses at all.
            let items = (0..30)
                .map(|i| FixedBytes::new([i as u8; 300]))
                .collect::<Vec<_>>();
            let mut journal =
                Journal::<_, FixedBytes<300>>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
            for item in &items {
                journal.append(item).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen with a fresh page cache so sealed-blob full pages are cold.
            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(16)),
                ..cfg
            };
            let mut journal = Journal::<_, FixedBytes<300>>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.snapshot().await.unwrap();

            // Warm blobs 1 (positions 5..10) and 3 (positions 15..20) with one read each. The
            // faulted pages cover the neighboring positions asserted below.
            reader.read(6).await.unwrap();
            reader.read(16).await.unwrap();

            // Prove the interleave the batch will see: warm-blob positions are sync hits, and the
            // scattered positions in blobs 0, 2, and 4 are misses. The hit pass in read_many runs
            // before any miss I/O, so this is exactly the hit/miss split the call resolves.
            for hit in [5, 6, 15, 17] {
                assert!(reader.try_read_sync(hit).is_some(), "position {hit}");
            }
            let misses = [0, 3, 10, 12, 20, 21, 23];
            for miss in misses {
                assert!(reader.try_read_sync(miss).is_none(), "position {miss}");
            }

            // The misses decompose into runs [0], [3], [10], [12], [20, 21], [23]: four single-item
            // runs and one consecutive pair across three blobs, with hits interleaved between them.
            let positions = [0, 3, 5, 6, 10, 12, 15, 17, 20, 21, 23];
            let expected: Vec<_> = positions
                .iter()
                .map(|&p| items[p as usize].clone())
                .collect();
            let before = context.encode();
            assert_eq!(reader.read_many(&positions).await.unwrap(), expected);

            // The batch's hit/miss accounting must match the staged interleave exactly.
            let after = context.encode();
            assert_eq!(
                counter(&after, "second_cache_hits") - counter(&before, "second_cache_hits"),
                4
            );
            assert_eq!(
                counter(&after, "second_cache_misses") - counter(&before, "second_cache_misses"),
                misses.len() as u64
            );

            // A second pass serves the now-cached positions through the hit path and must agree.
            let before = context.encode();
            assert_eq!(reader.read_many(&positions).await.unwrap(), expected);
            let after = context.encode();
            assert_eq!(
                counter(&after, "second_cache_hits") - counter(&before, "second_cache_hits"),
                positions.len() as u64
            );
            assert_eq!(
                counter(&after, "second_cache_misses"),
                counter(&before, "second_cache_misses")
            );
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

            // Append 40 items across 4 blobs (0-3)
            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Prune to position 20 (removes blobs 0-1, keeps blobs 2-3)
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

            // Append 40 items across 4 blobs (0-3)
            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Test 1: Full replay
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(0, NZUsize!(20)).await.unwrap();
                futures::pin_mut!(stream);
                for i in 0..40u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(stream.next().await.is_none());
            }

            // Test 2: Partial replay from middle of blob
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(15, NZUsize!(20)).await.unwrap();
                futures::pin_mut!(stream);
                for i in 15..40u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(stream.next().await.is_none());
            }

            // Test 3: Partial replay from blob boundary
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(20, NZUsize!(20)).await.unwrap();
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
                let reader = journal.snapshot().await.unwrap();
                let res = reader.replay(0, NZUsize!(20)).await;
                assert!(matches!(res, Err(crate::journal::Error::ItemPruned(_))));
            }
            {
                let reader = journal.snapshot().await.unwrap();
                let res = reader.replay(19, NZUsize!(20)).await;
                assert!(matches!(res, Err(crate::journal::Error::ItemPruned(_))));
            }

            // Test 5: Replay from exactly at pruning boundary after prune
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(20, NZUsize!(20)).await.unwrap();
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
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(40, NZUsize!(20)).await.unwrap();
                futures::pin_mut!(stream);
                assert!(stream.next().await.is_none());
            }

            // Test 7: Replay beyond the end (should error)
            {
                let reader = journal.snapshot().await.unwrap();
                let res = reader.replay(41, NZUsize!(20)).await;
                assert!(matches!(
                    res,
                    Err(crate::journal::Error::ItemOutOfRange(41))
                ));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_replay_stops_after_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "replay-stops-after-error".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();
            for i in 0..30u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let (blob, _) = context
                .open(&cfg.data_partition(), &1u64.to_be_bytes())
                .await
                .unwrap();
            blob.write_at_sync(0, vec![0xFF; 1]).await.unwrap();

            {
                let cache = CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10));
                let mut writers = Vec::new();
                for blob_index in 0..3u64 {
                    let (blob, size) = context
                        .open(&cfg.data_partition(), &blob_index.to_be_bytes())
                        .await
                        .unwrap();
                    writers.push(
                        Writer::new(blob, size, cfg.write_buffer.get(), cache.clone())
                            .await
                            .unwrap(),
                    );
                }

                let mut states = Vec::new();
                for (blob_index, writer) in writers.iter().enumerate() {
                    let blob = blob_index as u64;
                    states.push(ReplayState::<_, u64> {
                        blob,
                        replay: Blob::Writer(writer).replay_from(0, NZUsize!(1024)).unwrap(),
                        budget: 1024,
                        pos: blob * 10,
                        end_pos: (blob + 1) * 10,
                        offset: 0,
                        codec_config: (),
                        compressed: false,
                        _marker: PhantomData,
                    });
                }

                let stream = crate::journal::contiguous::replay_stream_from_states(states);
                futures::pin_mut!(stream);

                for i in 0..10u64 {
                    let (pos, item) = stream.next().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, i * 100);
                }
                assert!(matches!(
                    stream.next().await.unwrap(),
                    Err(Error::Corruption(_))
                ));
                assert!(stream.next().await.is_none());
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

            // Append items across 4 blobs: [0-9], [10-19], [20-29], [30-39]
            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Initial state: all items accessible
            let bounds = journal.bounds();
            assert_eq!(bounds.start, 0);
            assert_eq!(bounds.end, 40);

            // First prune: remove blob 0 (positions 0-9)
            let pruned = journal.prune(10).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at blob boundary
            assert_eq!(journal.bounds().start, 10);

            // Items 0-9 should be pruned, 10+ should be accessible
            assert!(matches!(
                journal.read(0).await,
                Err(crate::journal::Error::ItemPruned(_))
            ));
            assert_eq!(journal.read(10).await.unwrap(), 1000);
            assert_eq!(journal.read(19).await.unwrap(), 1900);

            // Second prune: remove blob 1 (positions 10-19)
            let pruned = journal.prune(20).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at blob boundary
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

            // Third prune: remove blob 2 (positions 20-29)
            let pruned = journal.prune(30).await.unwrap();
            assert!(pruned);

            // Variable-specific guarantee: oldest is EXACTLY at blob boundary
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

    /// Test recovery from crash after data blobs pruned but before offsets journal.
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

            // Append 40 items across 4 blobs to both journals
            for i in 0..40u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            // Prune to position 10 normally (both data and offsets journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.bounds().start, 10);

            // === Simulate crash: Prune data blobs but not offsets journal ===
            // Manually prune data blobs to blob 2 (position 20)
            variable.test_prune_data(2).await.unwrap();
            // Offsets journal still has data from position 10-19

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: offsets journal pruned to match data blobs
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

    /// A crash after data pruning but before offsets pruning must remain recoverable even when
    /// the last durable offsets end is below the new data boundary.
    #[test_traced]
    fn test_variable_recovery_prune_crash_offsets_end_behind() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-prune-offsets-end-behind".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Persist offsets only through position 7, then append enough unsynced items for a
            // prune to advance the data boundary beyond that durable offsets end.
            for i in 0..7u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            for i in 7..12u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Drop the production prune future while it is parked after the data-blob
            // removal, before offsets.prune has made the appended offsets durable: a
            // genuine cancellation at that await.
            journal.halt_before_offsets_prune = true;
            {
                let fut = journal.prune(10);
                futures::pin_mut!(fut);
                assert!(
                    futures::poll!(fut.as_mut()).is_pending(),
                    "prune must park before offsets.prune"
                );
            }
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .expect("prune crash must leave a recoverable journal");
            assert_eq!(journal.bounds(), 10..12);
            for i in 10..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery detects corruption when offsets journal pruned ahead of data blobs.
    ///
    /// Simulates an impossible state (offsets journal pruned more than data blobs) which
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

            // Append 40 items across 4 blobs to both journals
            for i in 0..40u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            // Prune offsets journal ahead of data blobs (impossible state)
            variable.test_prune_offsets(20).await.unwrap(); // Prune to position 20
            variable.test_prune_data(1).await.unwrap(); // Only prune data blobs to blob 1 (position 10)

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify corruption detected ===
            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Offsets journal is empty but in a different blob than data. This is an impossible state:
    /// both journals are always created in the same blob by init or init_at_size.
    #[test_traced]
    fn test_variable_recovery_offsets_empty_different_blob_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets-empty-diff-blob".into(),
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

            // Clear offsets to blob 2 (position 20) while data starts at blob 0.
            // This puts them in different blobs with offsets empty (bounds 20..20).
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

            // Prune data to blob 1 (position 10), but rewind offsets to 5 (so offsets_bounds is 0..5).
            // offsets_bounds.end = 5 < data_oldest_pos = 10.
            journal.test_prune_data(1).await.unwrap();
            journal.test_rewind_offsets(5).await.unwrap();
            drop(journal);

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Offsets start is mid-blob ahead of data's blob-aligned start, but in the same
    /// blob. This is the valid state left by init_at_size.
    #[test_traced]
    fn test_variable_recovery_offsets_start_mid_blob_ahead_of_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "offsets-mid-blob-ahead".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // init_at_size(7) creates offsets starting at position 7 (mid-blob 0), while
            // data's first blob is blob 0 (position 0). offsets.start > data_oldest_pos
            // but same blob.
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

    /// A crash after appending to the data blobs but before the offsets entries became durable
    /// leaves an unindexed data suffix, which init truncates (the items were never
    /// acknowledged).
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

            // Append 15 items to both journals (fills blob 0, partial blob 1)
            for i in 0..15u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            assert_eq!(variable.size(), 15);

            // Manually append 5 more items directly to data blobs only
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

            // The offsets journal is the record: the unindexed data suffix was never
            // acknowledged, so init truncates it.
            let bounds = variable.bounds();
            assert_eq!(bounds.end, 15);
            assert_eq!(bounds.start, 0);

            for i in 0..15u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }
            assert_eq!(variable.test_offsets_size(), 15);

            variable.destroy().await.unwrap();
        });
    }

    /// Data with no offsets entries at all was never acknowledged: init discards it entirely.
    #[test_traced]
    fn test_variable_recovery_discards_fully_unindexed_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-overlong-data-blob".into(),
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

            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            assert_eq!(journal.append(&42).await.unwrap(), 0);
            assert_eq!(journal.read(0).await.unwrap(), 42);
            journal.destroy().await.unwrap();
        });
    }

    /// Filling a blob makes it (and its offsets entries) durable at rollover, so a crash
    /// loses only the unsynced partial tail, never a filled blob.
    #[test_traced]
    fn test_variable_recovery_rollover_makes_filled_blobs_durable() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = Config::<()> {
                partition: "recovery-rollover-durable".into(),
                items_per_section: NZU64!(2),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // Fill blobs 0 and 1 (positions 0..4) and stage one unsynced item in blob 2,
            // then crash without ever calling sync.
            for i in 0..5u64 {
                assert_eq!(journal.append(&(i * 100)).await.unwrap(), i);
            }
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = Config::<()> {
                partition: "recovery-rollover-durable".into(),
                items_per_section: NZU64!(2),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };
            let mut journal = Journal::<_, u64>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            // The filled blobs survived (synced at rollover). The partial tail item vanished.
            assert_eq!(journal.bounds(), 0..4);
            for i in 0..4u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert_eq!(journal.append(&42).await.unwrap(), 4);
            assert_eq!(journal.read(4).await.unwrap(), 42);
            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest data blob is empty, a newer blob still holds durable
    /// items, and the offsets journal is gone: with no offsets entries, no data is
    /// acknowledged, so recovery aligns the journal to empty and discards the orphans.
    #[test_traced]
    fn test_variable_recovery_empty_oldest_blob_orphaned_newer_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-empty-oldest-blob".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            // Durably persist blobs 0 and 1 (positions 0..20).
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Empty the oldest data blob in place, leaving blob 1's items orphaned past the
            // gap, then drop the offsets journal so recovery rebuilds from the data alone.
            let data_partition = cfg.data_partition();
            let mut names = context.scan(&data_partition).await.unwrap();
            names.sort();
            assert_eq!(names.len(), 3);
            let (blob0, size0) = context.open(&data_partition, &names[0]).await.unwrap();
            assert!(size0 > 0, "blob 0 should start durable");
            blob0.resize(0).await.unwrap();
            blob0.sync().await.unwrap();
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

            // The orphaned newer blob is truncated away and appends resume from position 0.
            assert_eq!(journal.append(&42).await.unwrap(), 0);
            assert_eq!(journal.read(0).await.unwrap(), 42);
            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(
                data_blobs.len(),
                1,
                "orphaned newer blob should be truncated away"
            );

            journal.destroy().await.unwrap();
        });
    }

    /// Test that a crash partway through a multi-blob sync leaves a contiguous durable prefix
    /// that recovery preserves.
    ///
    /// `flush_dirty_data` syncs dirty data blobs before syncing offsets. This reproduces a
    /// crash after blobs 0 and 1 were synced but before blob 2 and the offsets journal were,
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

            // Fill blobs 0 and 1 and partially fill blob 2 (positions 20..25). Nothing is
            // synced yet, so only the created blob files are durable, all still empty.
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            // Sync blobs 0 and 1 but not blob 2 (and not offsets), simulating a crash after
            // part of a multi-blob sync became durable.
            journal.test_sync_data_blob(0).await.unwrap();
            journal.test_sync_data_blob(1).await.unwrap();
            drop(journal);

            // The durable data is exactly the contiguous prefix: blobs 0 and 1 hold items,
            // blob 2 is an empty trailing blob, and offsets never synced.
            let data_partition = cfg.data_partition();
            let mut names = context.scan(&data_partition).await.unwrap();
            names.sort();
            assert_eq!(names.len(), 3);
            for (blob, name) in names.iter().enumerate() {
                let (_blob, size) = context.open(&data_partition, name).await.unwrap();
                if blob < 2 {
                    assert!(size > 0, "blob {blob} should be durable");
                } else {
                    assert_eq!(size, 0, "blob {blob} should be empty");
                }
            }

            // Recovery trims the empty trailing blob, rebuilds offsets from the durable data, and
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

            // The empty trailing blob is adopted as the tail; appends continue from the
            // recovered end.
            let data_blobs = context.scan(&cfg.data_partition()).await.unwrap();
            assert_eq!(data_blobs.len(), 3);
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

            // Append 50 items across 5 blobs to both journals
            for i in 0..50u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            // Prune to position 10 normally (both data and offsets journals pruned)
            variable.prune(10).await.unwrap();
            assert_eq!(variable.bounds().start, 10);

            // === Simulate crash: Multiple prunes on data blobs, not on offsets journal ===
            // Manually prune data blobs to blob 3 (position 30)
            variable.test_prune_data(3).await.unwrap();
            // Offsets journal still thinks oldest is position 10

            variable.sync().await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init should auto-repair: offsets journal pruned to match data blobs
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

    /// A durably rewound offsets journal (the first step of `rewind`) with untouched data is a
    /// crash mid-rewind: init completes the rewind, discarding the data past the offsets end.
    #[test_traced]
    fn test_variable_recovery_offsets_rewound_behind_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // === Setup: Create Variable wrapper with data across multiple blobs ===
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

            // Append 25 items across 3 blobs (blob 0: 0-9, blob 1: 10-19, blob 2: 20-24)
            for i in 0..25u64 {
                variable.append(&(i * 100)).await.unwrap();
            }

            assert_eq!(variable.size(), 25);

            // Durably keep offsets for positions 0-4, while data still contains all 25 items.
            variable.test_rewind_offsets(5).await.unwrap();
            drop(variable);

            // === Verify recovery ===
            let mut variable = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init completes the rewind: positions 5.. were discarded with the offsets.
            let bounds = variable.bounds();
            assert_eq!(bounds.end, 5);
            assert_eq!(bounds.start, 0);
            for i in 0..5u64 {
                assert_eq!(variable.read(i).await.unwrap(), i * 100);
            }
            assert_eq!(variable.test_offsets_size(), 5);

            // Verify next append gets position 5
            let pos = variable.append(&500).await.unwrap();
            assert_eq!(pos, 5);
            assert_eq!(variable.read(5).await.unwrap(), 500);

            variable.destroy().await.unwrap();
        });
    }

    /// Offsets durably ahead of the data (a crash between the offsets rollover sync and the
    /// data sync) are rewound to the largest entry the durable data backs.
    #[test_traced]
    fn test_variable_recovery_offsets_ahead_rewound_to_durable_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-offsets-ahead-tail".into(),
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

            // Durably rewind the DATA to position 12: the offsets journal (ending at 20) is
            // now ahead of the durable data.
            journal.test_rewind_data_to_position(12).await.unwrap();
            journal.test_sync_data().await.unwrap();
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

    /// Offsets ahead of durable data that ends exactly at a blob boundary rewind to the
    /// boundary.
    #[test_traced]
    fn test_variable_recovery_offsets_ahead_boundary_data_rewound() {
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
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            journal.destroy().await.unwrap();
        });
    }

    /// An interior data blob shorter than its offsets entries claim holds acknowledged data
    /// that no longer exists: corruption.
    #[test_traced]
    fn test_variable_recovery_short_interior_data_blob_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-short-blob-after-anchor".into(),
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

            // The end of position 11's frame within blob 1.
            let offset = {
                let offsets = journal.offsets.snapshot().await.unwrap();
                offsets.read(11).await.unwrap()
            };
            drop(journal);

            // Truncate blob 1 in place (keeping blob 2) by reopening its blob directly.
            let (blob, size) = context
                .open(&cfg.data_partition(), &1u64.to_be_bytes())
                .await
                .unwrap();
            let mut writer = Writer::new(blob, size, 1024, cfg.page_cache.clone())
                .await
                .unwrap();
            writer.resize(offset).await.unwrap();
            writer.sync().await.unwrap();
            drop(writer);

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A partial trailing offsets entry cannot arise from a crash and is corruption.
    #[test_traced]
    fn test_variable_init_rejects_partial_offsets_entry() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
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

            // Durably extend the offsets blob by one byte (a partial entry).
            let (blob, raw_size) = context
                .open(&offsets_blob_partition, &0u64.to_be_bytes())
                .await
                .unwrap();
            assert_eq!(raw_size, expected_size);
            blob.write_at_sync(raw_size, vec![0u8]).await.unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
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
                let mut append = Writer::new(
                    blob,
                    raw_size,
                    2048,
                    CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                )
                .await
                .unwrap();
                let expected_size = append.size();
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
            assert_eq!(append.size(), expected_size);
        });
    }

    /// A crash after data sync but before any offsets sync (journal previously emptied by
    /// pruning) leaves unindexed data that init truncates.
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

            // === Phase 1: Create journal with one full blob ===
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Append 10 items (positions 0-9), fills blob 0
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

            // === Phase 3: Append directly to data blobs to simulate crash ===
            // Manually append to data blobs only (bypassing Variable's append logic)
            // This simulates the case where data was synced but offsets wasn't
            for i in 10..20u64 {
                journal.test_append_data(1, i * 100).await.unwrap();
            }
            // Sync the data blobs (blob 1)
            journal.test_sync_data().await.unwrap();
            // Do NOT sync offsets journal - simulates crash before offsets.sync()

            // Close without syncing offsets
            drop(journal);

            // === Phase 4: Verify recovery succeeds ===
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .expect("Should recover from crash after data sync but before offsets sync");

            // The unindexed data was never acknowledged, so init truncates it and the journal
            // remains empty at the pruning boundary.
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 10);

            // Items 0-9 should be pruned
            for i in 0..10 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            journal.destroy().await.unwrap();
        });
    }

    /// `commit` persists data then offsets, so a crash right after it loses nothing.
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

            // Append items across a blob boundary
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
    fn test_variable_recovery_from_mid_blob_durable_anchor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "mid-blob-durable-anchor".into(),
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
    fn test_init_at_size_rejects_conflicting_offsets_partitions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-conflicting-offsets".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };
            let legacy_partition = cfg.offsets_partition();
            let blobs_partition = format!("{legacy_partition}-blobs");

            for partition in [&legacy_partition, &blobs_partition] {
                let (blob, _) = context.open(partition, &0u64.to_be_bytes()).await.unwrap();
                blob.write_at_sync(0, vec![0]).await.unwrap();
            }

            let result = Journal::<_, u64>::init_at_size(context.child("storage"), cfg, 7).await;
            assert!(matches!(result, Err(Error::Corruption(_))));

            // The consistency check must fail before staging a reset, which would erase the
            // conflicting partitions and their corruption evidence.
            assert_eq!(context.scan(&legacy_partition).await.unwrap().len(), 1);
            assert_eq!(context.scan(&blobs_partition).await.unwrap().len(), 1);
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
    fn test_init_at_size_blob_boundary() {
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

            // Initialize at position 10 (exactly at blob 1 boundary with items_per_section=5)
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
    fn test_init_at_size_mid_blob() {
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

            // Initialize at position 7 (middle of blob 1 with items_per_section=5)
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
                // Simulate a crash right after `init_at_size(7)`'s batch landed: both blob
                // partitions removed and the offsets boundary recorded, before any tail blob
                // was recreated (with_tail=false) or after the empty offsets tail was
                // recreated (with_tail=true).
                let intent_ctx = context.child("intent").with_attribute("index", index);
                let mut checkpoint = super::super::checkpoint::Checkpoint::open(
                    intent_ctx.child("meta"),
                    &offsets_cfg.partition,
                )
                .await
                .unwrap();
                checkpoint.set_boundary_hint(7).await.unwrap();
                drop(checkpoint);
                Partition::<deterministic::Context>::remove_all(&context, &cfg.data_partition())
                    .await
                    .unwrap();
                Partition::<deterministic::Context>::remove_all(
                    &context,
                    &format!("{}-blobs", offsets_cfg.partition),
                )
                .await
                .unwrap();
                if clear_data {
                    let (blob, _) = context
                        .open(
                            &format!("{}-blobs", offsets_cfg.partition),
                            &1u64.to_be_bytes(),
                        )
                        .await
                        .unwrap();
                    blob.sync().await.unwrap();
                    drop(blob);
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

            // Plant a stale mid-blob boundary record (behind the live blob state): the reset
            // must overwrite it along with everything else.
            let offsets_cfg = fixed::Config {
                partition: cfg.offsets_partition(),
                items_per_blob: cfg.items_per_section,
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            };
            let stale_ctx = context.child("stale");
            let mut checkpoint = super::super::checkpoint::Checkpoint::open(
                stale_ctx.child("meta"),
                &offsets_cfg.partition,
            )
            .await
            .unwrap();
            checkpoint.set_boundary_hint(3).await.unwrap();
            drop(checkpoint);

            // init_at_size(10) overwrites the stale record and resets to 10.
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
    fn test_init_at_size_discards_same_blob_stale_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-discards-same-blob-stale-data".into(),
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

    /// Test init_at_size with mid-blob value persists correctly across restart.
    #[test_traced]
    fn test_init_at_size_mid_blob_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-mid-blob".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (mid-blob, 7 % 5 = 2)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 3 items at positions 7, 8, 9 (fills rest of blob 1)
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

    /// Test init_at_size mid-blob with data spanning multiple blobs.
    #[test_traced]
    fn test_init_at_size_mid_blob_multi_blob_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "init-at-size-multi-blob".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            // Initialize at position 7 (mid-blob)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 8 items: positions 7-14 (blob 1: 3 items, blob 2: 5 items)
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

    /// Removing every data blob while the offsets journal still holds entries cannot arise
    /// from a crash (the tail blob always exists): corruption.
    #[test_traced]
    fn test_variable_recovery_missing_data_blobs_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "align-journals-mid-blob-pruning-boundary".into(),
                items_per_section: NZU64!(5),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&(100 + i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            Partition::<deterministic::Context>::remove_all(&context, &cfg.data_partition())
                .await
                .unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
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

            // Initialize at position 7 (mid-blob)
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 3 items
            for i in 0..3u64 {
                journal.append(&(700 + i)).await.unwrap();
            }

            // The appends filled blob 1, so the rollover already made both the data and its
            // offsets entries durable. Crash without an explicit sync.
            drop(journal);

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

            // Prune to a position within the same blob should not move bounds.start backwards.
            journal.prune(8).await.unwrap();
            assert_eq!(journal.bounds().start, 7);
            assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));
            assert_eq!(journal.read(7).await.unwrap(), 700);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_recovery_near_max_data_synced_offsets_not() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "near-max-data-synced-offsets-not".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), u64::MAX - 1)
                    .await
                    .unwrap();
            assert_eq!(journal.append(&7).await.unwrap(), u64::MAX - 1);
            journal
                .test_sync_data_blob(position_to_blob(u64::MAX - 1, cfg.items_per_section.get()))
                .await
                .unwrap();
            drop(journal);

            // The item's offsets entry never became durable, so init discards it.
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), (u64::MAX - 1)..(u64::MAX - 1));

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

            // Create initial journal with data in multiple blobs
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-19 (blobs 0-3 with items_per_section=5)
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that overlap with existing data
            // lower_bound: 8 (blob 1), upper_bound: 31 (last location 30, blob 6)
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

            // Verify oldest retained is pruned to lower_bound's blob boundary (5)
            assert_eq!(journal.bounds().start, 5); // Blob 1 starts at position 5

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

            // Add data at positions 0-19 (blobs 0-3 with items_per_section=5)
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that exactly match existing data
            let lower_bound = 5; // blob 1
            let upper_bound = 20; // blob 3
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with exact match");

            assert_eq!(journal.size(), 20);

            // Verify pruning to lower bound (blob 1 boundary = position 5)
            assert_eq!(journal.bounds().start, 5); // Blob 1 starts at position 5

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

            // Add data at positions 0-29 (blobs 0-5 with items_per_section=5)
            for i in 0..30u64 {
                journal.append(&(i * 1000)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries that are exceeded by existing data
            let lower_bound = 8; // blob 1
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

            // Add data at positions 0-9 (blobs 0-1 with items_per_section=5)
            for i in 0..10u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Initialize with sync boundaries beyond all existing data
            let lower_bound = 15; // blob 3
            let upper_bound = 26; // last element in blob 5
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

    /// Test `init_sync` with blob boundary edge cases.
    #[test_traced]
    fn test_init_sync_blob_boundaries() {
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

            // Create journal with data at blob boundaries
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-24 (blobs 0-4 with items_per_section=5)
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Test sync boundaries exactly at blob boundaries
            let lower_bound = 15; // Exactly at blob boundary (15/5 = 3)
            let upper_bound = 25; // Last element exactly at blob boundary (24/5 = 4)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal at boundaries");

            assert_eq!(journal.size(), 25);

            // Verify oldest retained is at blob 3 boundary (position 15)
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

    /// Test `init_sync` when range.start and range.end-1 are in the same blob.
    #[test_traced]
    fn test_init_sync_same_blob_bounds() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let items_per_section = NZU64!(5);
            let cfg = Config {
                partition: "test-same-blob".into(),
                items_per_section,
                compression: None,
                codec_config: (),
                write_buffer: NZUsize!(1024),
                page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(PAGE_CACHE_SIZE)),
            };

            // Create journal with data in multiple blobs
            let mut journal =
                Journal::<deterministic::Context, u64>::init(context.child("storage"), cfg.clone())
                    .await
                    .expect("Failed to create initial journal");

            // Add data at positions 0-14 (blobs 0-2 with items_per_section=5)
            for i in 0..15u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Test sync boundaries within the same blob
            let lower_bound = 10; // operation 10 (blob 2: 10/5 = 2)
            let upper_bound = 15; // Last operation 14 (blob 2: 14/5 = 2)
            let mut journal = Journal::<deterministic::Context, u64>::init_sync(
                context.child("storage"),
                cfg.clone(),
                lower_bound..upper_bound,
            )
            .await
            .expect("Failed to initialize journal with same-blob bounds");

            assert_eq!(journal.size(), 15);

            // Both operations are in blob 2, so blobs 0, 1 should be pruned, blob 2 retained
            // Oldest retained position should be at blob 2 boundary (position 10)
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
    fn test_single_item_per_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "single-item-per-blob".into(),
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

            // === Test 2: Multiple items with single item per blob ===
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

            // === Test 3: Pruning with single item per blob ===
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

            // === Test 4: Restart persistence with single item per blob ===
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

            // Append 25 items (spanning multiple blobs)
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
            let reader = journal.snapshot().await.unwrap();
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
                "variable_metrics_items_read_total 4",
                "variable_metrics_commit_calls_total 1",
                "variable_metrics_sync_calls_total 1",
                "variable_metrics_append_duration_count 1",
                "variable_metrics_append_many_duration_count 1",
                "variable_metrics_read_duration_count 0",
                "variable_metrics_read_many_duration_count 1",
                "variable_metrics_commit_duration_count 1",
                "variable_metrics_sync_duration_count 1",
                "variable_metrics_cache_hits_total 4",
                "variable_metrics_cache_misses_total 0",
                "variable_metrics_data_tracked",
                "variable_metrics_offsets_size 4",
                "variable_metrics_offsets_blobs_tracked",
            ] {
                assert!(buffer.contains(expected), "{expected}\n{buffer}");
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_journal_read_miss_timed() {
        // Reads served from storage record a read_duration sample; cache hits do not.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Blobs span multiple full pages so their data must go through the (evictable)
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
            let reader = journal.snapshot().await.unwrap();
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

            let snapshot = journal.snapshot().await.unwrap();
            assert_eq!(snapshot.bounds(), 0..7);

            // Appending past the blob boundary rolls the snapshot's tail blob into
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

            let fresh = journal.snapshot().await.unwrap();
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

            let snapshot = journal.snapshot().await.unwrap();
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

            let fresh = journal.snapshot().await.unwrap();
            assert_eq!(fresh.bounds(), 10..17);
            assert!(matches!(fresh.read(3).await, Err(Error::ItemPruned(3))));

            drop(snapshot);
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
                futures::channel::mpsc::channel::<Reader<'static, deterministic::Context, u64>>(8);
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
                    let snapshot = journal.snapshot().await.unwrap();
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
            let snapshot = journal.snapshot().await.unwrap();
            assert_eq!(snapshot.bounds(), 0..7);

            // Roll the snapshot's tail into history, then prune both of its blobs away.
            for i in 7..23u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            assert!(journal.prune(12).await.unwrap());

            {
                let stream = snapshot.replay(0, NZUsize!(1024)).await.unwrap();
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

    /// A journal written before eager tail creation can end with a full newest blob and no
    /// successor file; recovery opens the missing tail.
    #[test_traced]
    fn test_variable_recovery_full_newest_blob_without_successor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-full-newest-no-successor".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(&context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            };

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..10u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Remove the empty tail blob, leaving only the full blob 0 (the layout written
            // before eager tail creation).
            let data_partition = cfg.data_partition();
            context
                .remove(&data_partition, Some(&1u64.to_be_bytes()))
                .await
                .unwrap();

            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..10);
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            assert_eq!(journal.append(&1000).await.unwrap(), 10);
            assert_eq!(journal.read(10).await.unwrap(), 1000);

            journal.destroy().await.unwrap();
        });
    }

    /// A crash after `rewind` durably truncated the offsets journal but before the data was
    /// truncated leaves offsets behind data. Recovery completes the rewind by discarding the
    /// data past the offsets end.
    #[test_traced]
    fn test_variable_rewind_crash_before_data_truncation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "rewind-crash-offsets-only".into(),
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

            // `rewind` durably truncates offsets before the data. Simulate a crash in between.
            journal.test_rewind_offsets(12).await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..12);
            for i in 0..12u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }

            journal.destroy().await.unwrap();
        });
    }

    /// Retained data blobs must be contiguous; recovery rejects a missing interior blob.
    #[test_traced]
    fn test_variable_recovery_rejects_gap_in_retained_blobs() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                partition: "recovery-gap-in-retained-blobs".into(),
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
            drop(journal);

            // Remove blob 1, leaving a gap in the retained data blobs.
            context
                .remove(&cfg.data_partition(), Some(&1u64.to_be_bytes()))
                .await
                .unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Drive a rewind plus a rollover-crossing unsynced append through a crash, on plain
    /// MemStorage and again under the volume backend: both provide per-blob atomic sync, so
    /// recovery lands on the same state (the rewound prefix plus the blob sealed at rollover).
    fn variable_rewind_rollover_crash(runner: deterministic::Runner) {
        fn test_cfg(context: &deterministic::Context) -> Config<()> {
            Config {
                partition: "rewind-rollover-crash".into(),
                items_per_section: NZU64!(10),
                compression: None,
                codec_config: (),
                page_cache: CacheRef::from_pooler(context, LARGE_PAGE_SIZE, NZUsize!(10)),
                write_buffer: NZUsize!(1024),
            }
        }

        let (_, checkpoint) = runner.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Durably persist 25 items, rewind to 15 (immediately durable), then append 8
            // replacement items without syncing: the rollover at position 20 seals blob 1
            // durably while positions 20..23 stay unsynced in blob 2.
            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.rewind(15).await.unwrap();
            for i in 15..23u64 {
                journal.append(&(i * 1000)).await.unwrap();
            }
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context);
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..20);
            for i in 0..15u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            for i in 15..20u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 1000);
            }
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_rewind_rollover_crash_memory() {
        variable_rewind_rollover_crash(deterministic::Runner::default());
    }

    #[test_traced]
    fn test_variable_rewind_rollover_crash_volume() {
        variable_rewind_rollover_crash(deterministic::Runner::new(
            deterministic::Config::default()
                .with_storage_volume(deterministic::VolumeConfig::default()),
        ));
    }
}
