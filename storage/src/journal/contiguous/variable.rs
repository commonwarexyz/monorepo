//! Position-based journal for variable-length items.
//!
//! # Format
//!
//! Items are stored as varint-framed records in ONE data blob (`b"data"` in
//! `{partition}_data`). A parallel offsets journal (a single-blob [super::fixed] journal of
//! `u64`s in `{partition}_offsets`) records, for each position, the absolute byte offset one
//! past its frame's end in the data blob: frame `i` spans `[entry[i - 1], entry[i])`, and the
//! first RETAINED frame starts at the data blob's pruned floor.
//!
//! ```text
//! data:    +---------+---------+-----+-----------+
//!          | frame_0 | frame_1 | ... | frame_n-1 |
//!          +---------+---------+-----+-----------+
//! offsets: | end_0   | end_1   | ... | end_n-1   |
//! ```
//!
//! # Pruning
//!
//! `prune(min_position)` prunes both sides exactly: the offsets journal to `min_position` and
//! the data blob to the byte where `min_position`'s frame begins (both native
//! [commonware_runtime::Blob::prune] floors are byte-exact). The pruning boundary IS the
//! requested position — no section alignment, no retained slack.
//!
//! # Crash reconciliation
//!
//! Each blob's pruned floor is a mutation whose durability follows a commit capturing that
//! blob, and a crash regresses each floor to its own last-committed value (never forward),
//! so consumers re-prune after recovery. Whether frame bytes in a regressed range hold
//! their original content is backend-defined ([commonware_runtime::Blob::prune]): the
//! volume resurfaces them, raw file backends may have reclaimed the space, and this
//! journal never reads below its own boundary either way.
//! `prune` stages both blobs in ONE batch whose commit captures both floors, so a crash
//! ordinarily recovers a consistent pair. The [commonware_runtime::Blob] contract still ties
//! each floor to its own blob's commits with no cross-blob pairing promised (and the
//! test-only sequential batch fallback replays staged syncs in order), so init reconciles
//! rather than assuming the pair:
//!
//! - Within `prune`, the DATA blob's native prune and staged sync always precede the offsets
//!   journal's. The pending floor pair is therefore only ever (old, old), (new, old), or
//!   (new, new): a commit can adopt the data floor without the offsets floor, never the
//!   reverse, so across a crash the data floor can be AHEAD of the offsets boundary (entries
//!   retained whose bytes are pruned) but never behind it.
//! - On init the more advanced side is authoritative: the first retained entry ending past
//!   the data floor names the true boundary, and the offsets journal is re-pruned to it
//!   (pruning is idempotent and cheap). This order is load-bearing — it keeps the entry that
//!   locates the first surviving frame retained. Had the offsets side been allowed to run
//!   ahead instead, the entry recording where the first retained frame begins would already
//!   be pruned and the data floor could not be interpreted (an undetectable state).
//!
//! # Recovery
//!
//! The storage backend restores every blob to exactly its last-synced state after a crash,
//! and every mutation stages both blobs in ONE atomic batch, so recovery is verification plus
//! the floor reconciliation above — never repair: the data blob must end exactly at the frame
//! end recorded by the last offsets entry (at its floor when no entries are retained), and no
//! frame is ever scanned or decoded.
//!
//! # Clearing / reset
//!
//! Clearing wipes all data and restarts the journal at a new size: the offsets journal
//! materializes its fully pruned image and the data blob truncates to its floor, committed
//! together. A clear at or above the offsets journal's pruning boundary transforms both blobs
//! in place and is all-or-nothing: a crash recovers either the prior state or the cleared
//! one. A clear BELOW the boundary must remove and recreate both partitions (nothing may
//! shrink below a floor), so a crash between the removals' commit and the new image's commit
//! recovers an EMPTY journal at position 0 — never fabricated items — and the sync flows that
//! clear backwards re-clear on reopen.

use super::{fixed, metrics::Metrics, Blob, Contiguous, Many, Mutable, Replay as BlobReplay};
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
use std::{io::Cursor, marker::PhantomData, num::NonZeroUsize, ops::Range, sync::Arc};
#[commonware_macros::stability(ALPHA)]
use tracing::debug;

/// Name of the single blob holding all frames.
const BLOB_NAME: &[u8] = b"data";

/// Suffix appended to the base partition name for the data blob's partition.
const DATA_SUFFIX: &str = "_data";

/// Suffix appended to the base partition name for the offsets journal's partition.
const OFFSETS_SUFFIX: &str = "_offsets";

/// Items encoded for a deferred append, created by [`Journal::prepare_append`] and consumed by
/// [`Journal::append_prepared`].
pub struct PreparedAppend<V> {
    encoded: Vec<u8>,
    item_starts: Vec<usize>,
    compressed: bool,
    _marker: PhantomData<V>,
}

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

/// Replay state over the journal's data blob.
///
/// Unlike fixed replay, each yielded item must first decode a varint frame length. The byte
/// `budget` caps how much frame data this state emits in one stream batch.
struct ReplayState<'a, B: RBlob, V: Codec> {
    /// Sequential logical bytes for the data blob.
    replay: BlobReplay<'a, B>,
    /// Target maximum number of encoded bytes decoded per batch.
    budget: u64,
    /// Next position to yield.
    pos: u64,
    /// Exclusive end position.
    end_pos: u64,
    /// Byte offset of the next frame.
    offset: u64,
    /// Codec configuration for decoded items.
    codec_config: V::Cfg,
    /// Whether frame payloads are compressed.
    compressed: bool,
    _marker: PhantomData<V>,
}

impl<B: RBlob, V: CodecShared> super::ReplayBatchState for ReplayState<'_, B, V> {
    type Item = V;

    /// Decode the next batch of varint-framed items.
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
                        "data blob ended before position {}",
                        self.pos
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
                            "incomplete frame header in the data blob at offset {}",
                            self.offset
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
                        "incomplete frame in the data blob at offset {}",
                        self.offset
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

    /// Optional compression level for stored items.
    pub compression: Option<u8>,

    /// [Codec] configuration for encoding/decoding items.
    pub codec_config: C,

    /// Page cache for buffering reads from the underlying storage.
    pub page_cache: CacheRef,

    /// Write buffer size for each of the journal's two blobs.
    pub write_buffer: NonZeroUsize,
}

impl<C> Config<C> {
    /// Returns the partition name for the data blob.
    fn data_partition(&self) -> String {
        format!("{}{}", self.partition, DATA_SUFFIX)
    }

    /// Returns the partition name for the offsets journal.
    fn offsets_partition(&self) -> String {
        format!("{}{}", self.partition, OFFSETS_SUFFIX)
    }
}

/// Implementation of [super::Mutable] for variable-size value journals: one frame-encoded data
/// blob indexed by a [super::fixed] journal of frame-end offsets (see the module docs).
pub struct Journal<E: Context, V: Codec> {
    /// The storage context for data-blob operations.
    context: E,

    /// The partition holding [Self::data].
    data_partition: String,

    /// The single data blob holding every frame.
    data: Writer<E::Blob>,

    /// Index mapping each position to the byte offset one past its frame's end in [Self::data].
    /// A frame starts where its predecessor ends (the data blob's floor for the first retained
    /// frame).
    offsets: fixed::Journal<E, u64>,

    /// The readable positions; `bounds.end` is the next append position.
    ///
    /// # Invariant
    ///
    /// `bounds` equals the offsets journal's bounds, and the data blob's floor is the byte
    /// offset where `bounds.start`'s frame begins (the data blob's size when empty).
    bounds: Range<u64>,

    /// Whether the data blob has mutations not yet staged for durability.
    dirty: bool,

    /// The page cache backing [Self::data] (retained to rebuild it after a clear, an ALPHA
    /// path — hence the manual stability gate).
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    page_cache: CacheRef,

    /// The write buffer size for [Self::data] (retained to rebuild it after a clear, an ALPHA
    /// path — hence the manual stability gate).
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    write_buffer: NonZeroUsize,

    /// Optional compression level when encoding items.
    compression: Option<u8>,

    /// Codec configuration for decoding items.
    codec_config: V::Cfg,

    /// Journal and Reader metrics.
    metrics: Arc<Metrics<E>>,
}

/// A reader over a variable journal.
pub struct Reader<'a, E: Context, V: Codec> {
    /// The journal's data blob.
    data: Blob<'a, E::Blob>,

    /// The readable position range `[start, end)`.
    bounds: Range<u64>,

    /// Byte offset in the data blob where `bounds.start`'s frame begins (the data blob's
    /// floor when this reader was created).
    start_offset: u64,

    /// Maps each position to the byte offset one past its frame's end in the data blob.
    offsets: fixed::Reader<'a, E, u64>,

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

    /// Byte offset where `position`'s frame starts, if resolvable without I/O: the first
    /// retained frame starts at the captured floor, and any other frame starts where its
    /// predecessor's entry says it ends.
    fn frame_start_sync(&self, position: u64) -> Option<u64> {
        if position == self.bounds.start {
            return Some(self.start_offset);
        }
        self.offsets.try_read_sync(position - 1)
    }

    /// Byte offset where `position`'s frame starts, reading the predecessor entry if needed.
    async fn frame_start(&self, position: u64) -> Result<u64, Error> {
        if position == self.bounds.start {
            return Ok(self.start_offset);
        }
        self.offsets.read(position - 1).await
    }

    /// Read the varint-framed item at byte `offset`.
    async fn read_at_offset(&self, offset: u64) -> Result<V, Error> {
        read_frame_at(&self.data, offset, &self.codec_config, self.compressed)
            .await
            .map(|(_, _, item)| item)
    }

    /// Read consecutive items. `offsets` must be strictly increasing byte offsets of
    /// byte-adjacent frames.
    ///
    /// Returns [Error::Corruption] if the offsets are not strictly increasing or if the
    /// on-disk varint at any offset reports a size inconsistent with the gap to the next
    /// offset.
    async fn read_run(&self, offsets: &[u64]) -> Result<Vec<V>, Error> {
        // Trivial runs take the single-item path; there is nothing to batch.
        if offsets.len() <= 1 {
            let mut items = Vec::with_capacity(offsets.len());
            for &offset in offsets {
                items.push(self.read_at_offset(offset).await?);
            }
            return Ok(items);
        }

        for window in offsets.windows(2) {
            if window[1] <= window[0] {
                return Err(Error::Corruption(format!(
                    "non-increasing frame offsets: {} >= {}",
                    window[0], window[1]
                )));
            }
        }

        // Read the byte span covering every item but the last in one operation; the last item's
        // length is unknown, so it goes through the single-item path.
        let start = offsets[0];
        let end = offsets[offsets.len() - 1];
        let range_len = usize::try_from(end - start).map_err(|_| Error::OffsetOverflow)?;
        let bytes = self.data.read_at(start, range_len).await?.coalesce();
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
                return Err(Error::Corruption(format!(
                    "offset/data layout mismatch at offset {offset}: offsets journal \
                     expected {item_len}, data varint reports {actual_len}"
                )));
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

        items.push(self.read_at_offset(end).await?);
        Ok(items)
    }

    /// Read the varint-framed item at byte `offset` from cached bytes, returning `None` on any
    /// miss.
    fn try_read_frame_sync(&self, offset: u64, buf: &mut Vec<u8>) -> Option<V> {
        let remaining = self.data.size().checked_sub(offset)?;
        let header_len = usize::try_from(remaining.min(MAX_U32_VARINT_SIZE as u64)).ok()?;
        if header_len == 0 {
            return None;
        }

        // Read the varint header to determine item size.
        let mut header = [0u8; MAX_U32_VARINT_SIZE];
        if !self
            .data
            .try_read_sync_into(&mut header[..header_len], offset)
        {
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
        if !self.data.try_read_sync_into(buf, offset) {
            return None;
        }
        decode_item::<V>(
            &buf[varint_len..varint_len + data_len],
            &self.codec_config,
            self.compressed,
        )
        .ok()
    }

    /// Build the replay state for `[start_pos, bounds.end)`, or `None` when the range is empty.
    async fn replay_state(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<Option<ReplayState<'a, E::Blob, V>>, Error> {
        let bounds = self.bounds.clone();
        if start_pos > bounds.end {
            return Err(Error::ItemOutOfRange(start_pos));
        }
        if start_pos < bounds.start {
            return Err(Error::ItemPruned(start_pos));
        }
        if start_pos == bounds.end {
            return Ok(None);
        }

        // Store codec settings in the state because the stream owns the state across await
        // points and cannot borrow `self`.
        let offset = self.frame_start(start_pos).await?;
        Ok(Some(ReplayState::<E::Blob, V> {
            replay: self.data.clone().replay_from(offset, buffer)?,
            budget: buffer.get() as u64,
            pos: start_pos,
            end_pos: bounds.end,
            offset,
            codec_config: self.codec_config.clone(),
            compressed: self.compressed,
            _marker: PhantomData,
        }))
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
        // Group runs of consecutive positions (whose frames are byte-adjacent), then read all
        // runs concurrently.
        let mut runs = Vec::new();
        let mut run_start = 0;
        while run_start < miss_positions.len() {
            let mut run_end = run_start + 1;
            while run_end < miss_positions.len()
                && miss_positions[run_end - 1].checked_add(1) == Some(miss_positions[run_end])
            {
                run_end += 1;
            }
            runs.push((run_start, run_end));
            run_start = run_end;
        }

        let run_items = try_join_all(
            runs.iter()
                .map(|&(run_start, run_end)| self.read_run(&miss_offsets[run_start..run_end])),
        )
        .await?;
        for (&(run_start, _), items) in runs.iter().zip(run_items) {
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

        // A frame at position p spans [entry(p - 1), entry(p)) — starting at the captured
        // floor for the first retained position — so one batched pass over the offsets journal
        // resolves every queried frame's extent. Positions and their predecessors interleave
        // into one strictly increasing lookup list.
        let mut lookups: Vec<u64> = Vec::with_capacity(positions.len() * 2);
        for &position in positions {
            if position != self.bounds.start && position > 0 {
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

        // Split queried frames into known extents (served below by one batched cache read) and
        // unknown extents (start known but end lookup missed, served by the per-frame path).
        // Frames whose start could not be resolved stay `None`.
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
            let offset = if position == self.bounds.start {
                Some(self.start_offset)
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

        let mut hits = 0u64;

        // Serve known-extent frames with one batched cache read.
        if !extents.is_empty() {
            let ranges: Vec<(u64, usize)> = extents
                .iter()
                .map(|&(_, offset, len)| (offset, len))
                .collect();
            let total: usize = ranges.iter().map(|&(_, len)| len).sum();
            let mut buf = vec![0u8; total];
            let missed = self.data.try_read_ranges_sync_into(&mut buf, &ranges);
            let mut missed = missed.into_iter().peekable();
            let mut local = 0usize;
            for (range_idx, &(idx, _, len)) in extents.iter().enumerate() {
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
            if let Some(item) = self.try_read_frame_sync(offset, &mut frame_buf) {
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
    /// the frames with one batched pass per run. Returns one item per miss, in order.
    async fn fetch_misses(&self, misses: &[Miss]) -> Result<Vec<V>, Error> {
        if misses.is_empty() {
            return Ok(Vec::new());
        }

        // Validate before consulting the offsets journal so a probe-declined out-of-bounds
        // position surfaces as a range error rather than corruption.
        for miss in misses {
            self.validate_readable(miss.position)?;
        }

        // A frame start is its predecessor's entry. The boundary position resolves to the
        // captured floor in the sync pass and is never unresolved here.
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
                    Error::Corruption(format!("offsets entry should be found, but got: {e}"))
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
            if let Some(item) = self.try_read_frame_sync(offset, &mut buf) {
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
        self.metrics.cache_misses.inc();
        let item = self.read_at_offset(offset).await?;
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
        let item = self.try_read_frame_sync(offset, &mut buf)?;
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
        let state = self.replay_state(start_pos, buffer).await?;

        Ok(super::replay_stream(state))
    }
}

impl<E: Context, V: CodecShared> Journal<E, V> {
    /// Initialize a contiguous variable journal.
    ///
    /// # Crash Recovery
    ///
    /// Every mutation stages the offsets journal and the data blob in ONE batch, so init
    /// verifies that the two sides agree and reconciles their pruned floors (see the module
    /// docs). Any other disagreement is corruption.
    #[boxed]
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<Self, Error> {
        let mut offsets = fixed::Journal::<E, u64>::init(
            context.child("offsets"),
            fixed::Config {
                partition: cfg.offsets_partition(),
                page_cache: cfg.page_cache.clone(),
                write_buffer: cfg.write_buffer,
            },
        )
        .await?;

        let data_partition = cfg.data_partition();
        let data_context = context.child("data");
        let (raw, size) = data_context
            .open(&data_partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;

        // Verify the data blob against the offsets journal and reconcile the floors (which
        // may re-prune the offsets journal).
        let bounds = Self::recover_bounds(&mut offsets, &raw, size).await?;

        let data = Writer::new(raw, size, cfg.write_buffer.get(), cfg.page_cache.clone())
            .await
            .map_err(Error::Runtime)?;

        let metrics = Metrics::new(context);
        metrics.update(bounds.end, bounds.start);

        Ok(Self {
            context: data_context,
            data_partition,
            data,
            offsets,
            bounds,
            dirty: false,
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            page_cache: cfg.page_cache,
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            write_buffer: cfg.write_buffer,
            compression: cfg.compression,
            codec_config: cfg.codec_config,
            metrics: Arc::new(metrics),
        })
    }

    /// Verify the offsets journal against the data blob, reconcile the two pruned floors, and
    /// recover the journal bounds (see the module docs on recovery and crash reconciliation).
    ///
    /// Verification: with no retained entries the data blob must hold no retained bytes
    /// (size == floor), and otherwise it must end exactly at the last entry. Reconciliation:
    /// retained entries ending at or below the data floor index frames whose bytes are gone
    /// (the data floor committed ahead of the offsets floor), so the offsets journal is
    /// re-pruned to the first surviving frame — whose recorded start must equal the floor
    /// exactly, anything else being corruption.
    async fn recover_bounds(
        offsets: &mut fixed::Journal<E, u64>,
        raw: &E::Blob,
        size: u64,
    ) -> Result<Range<u64>, Error> {
        let mut bounds = offsets.pruning_boundary()..offsets.size();
        let floor = raw.floor();

        // With no retained entries the data blob must be empty of retained bytes: entries
        // become durable only in a batch that also captures the data bytes they index.
        if bounds.is_empty() {
            if size != floor {
                return Err(Error::Corruption(format!(
                    "data blob holds bytes {floor}..{size} but the offsets journal has no \
                     entries at {}",
                    bounds.end
                )));
            }
            return Ok(bounds);
        }

        // The data blob must end exactly at the last indexed frame's end.
        let last = offsets.read(bounds.end - 1).await?;
        if last != size {
            return Err(Error::Corruption(format!(
                "data blob holds {size} bytes but its entries end at {last}"
            )));
        }

        // Reconcile the floors. The first retained frame ending past the data floor is the
        // common case (the floors committed together). Anything before it was pruned from the
        // data blob ahead of the offsets journal.
        if offsets.read(bounds.start).await? <= floor {
            // Binary search for the first retained position whose frame ends past the floor
            // (entries are strictly increasing).
            let (mut lo, mut hi) = (bounds.start + 1, bounds.end);
            while lo < hi {
                let mid = lo + (hi - lo) / 2;
                if offsets.read(mid).await? <= floor {
                    lo = mid + 1;
                } else {
                    hi = mid;
                }
            }

            // The floor must be exactly where the first surviving frame begins (its
            // predecessor's recorded end). A floor inside a frame is not a state any prune
            // produces: corruption.
            let frame_start = offsets.read(lo - 1).await?;
            if frame_start != floor {
                return Err(Error::Corruption(format!(
                    "data floor {floor} falls inside the frame spanning {frame_start}..{}",
                    offsets.read(lo.min(bounds.end - 1)).await?
                )));
            }

            // Re-prune the laggard offsets journal to the authoritative boundary.
            let pruned = offsets.prune(lo).await?;
            debug_assert!(pruned, "the boundary strictly advances");
            bounds.start = lo;
        }

        Ok(bounds)
    }

    /// Initialize an empty [Journal] at the given logical `size`.
    ///
    /// This discards any existing data (the prior image must still be readable: a corrupt
    /// store fails initialization rather than being silently discarded). The journal returned
    /// has `bounds() == size..size` and the next append lands at position `size`.
    ///
    /// # Crash Safety
    ///
    /// The cleared image is durable when this call returns. A crash during the call recovers
    /// the journal in its prior state or with bounds `size..size` — except when `size`
    /// precedes the offsets journal's pruning boundary, which forces both partitions to be
    /// removed and recreated, and a crash between those two commits recovers an EMPTY journal
    /// at position 0 (see the module docs on clearing).
    #[commonware_macros::stability(ALPHA)]
    pub async fn init_at_size(context: E, cfg: Config<V::Cfg>, size: u64) -> Result<Self, Error> {
        let mut journal = Self::init(context, cfg).await?;
        journal.clear_to_size(size).await?;
        Ok(journal)
    }

    /// Initialize a [Journal] for use in state sync.
    ///
    /// The bounds are item locations. This function prepares the on-disk journal so that
    /// subsequent appends go to the correct physical location for the requested range.
    ///
    /// Behavior by existing on-disk state:
    /// - Fresh (no data): returns an empty journal, resetting to `range.start` if needed.
    /// - Stale (all data strictly before `range.start`): resets to `range.start` using the
    ///   crash-safe clear path and returns an empty journal.
    /// - Overlap within [`range.start`, `range.end`]: prunes to `range.start`, exactly.
    /// - Already pruned beyond the start (non-empty, pruning boundary above `range.start`):
    ///   returns the journal as-is, matching `qmdb/sync/journal.rs`.
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
            range.end, "initializing contiguous variable journal for sync"
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

        // After a crash during a previous clear_to_size, the journal may recover to a stale
        // position ahead of the requested start.
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
    /// Unlike appends, a rewind is durable when this call returns, and it is ATOMIC: the data
    /// blob's truncation, the offsets journal's truncation, and any still-dirty retained
    /// state land in ONE batch with one commit, so no crash can leave the two sides
    /// describing different histories.
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

        // The byte offset of the first discarded item's frame is the data truncation point.
        let offset = if size == self.bounds.start {
            self.data.floor()
        } else {
            self.offsets.read(size - 1).await?
        };

        // ONE batch stages the whole rewind, data before offsets (see the module docs on
        // staging order). Truncations stage full durability membership, so no dirty state
        // survives the commit.
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.data
            .resize_into(offset, &mut batch)
            .await
            .map_err(Error::Runtime)?;
        self.dirty = false;
        self.offsets.rewind_into(size, &mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)?;

        self.bounds.end = size;
        self.metrics.update(self.bounds.end, self.bounds.start);

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

        // Reject the append before writing anything (to either blob) if it would push the
        // size past `u64::MAX` items, past an offsets journal byte size that is
        // representable, or past a representable data byte offset.
        let end = self
            .bounds
            .end
            .checked_add(items_count as u64)
            .ok_or(Error::SizeOverflow)?;
        end.checked_mul(fixed::Journal::<E, u64>::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;
        let base = self.data.size();
        base.checked_add(encoded.len() as u64)
            .ok_or(Error::OffsetOverflow)?;

        // Frame ends are absolute byte offsets in the data blob.
        let ends: Vec<u64> = (0..items_count)
            .map(|item| {
                let frame_end = item_starts.get(item + 1).copied().unwrap_or(encoded.len());
                base + frame_end as u64
            })
            .collect();

        // Append the data bytes, then the entries indexing them. Both sides buffer, and the
        // next sync stages them in ONE batch, so durable entries can never describe data
        // bytes that were not captured by the same commit.
        self.data
            .append_owned(IoBuf::from(encoded))
            .await
            .map_err(Error::Runtime)?;
        self.dirty = true;
        let last = self.offsets.append_many(Many::Flat(&ends)).await?;
        assert_eq!(last, end - 1);

        self.bounds.end = end;
        self.metrics.update(self.bounds.end, self.bounds.start);
        Ok(end - 1)
    }

    /// Capture an owned snapshot ([`Reader`]) over the current journal. Bounds are frozen at
    /// creation, and the snapshot stays readable across concurrent appends.
    ///
    /// If the journal later rewinds or clears into the returned reader's range, subsequent
    /// reads from that range may observe unspecified contents. If the journal later PRUNES
    /// into the reader's range, reads of the pruned positions have THREE outcomes: a stale
    /// success (the bytes survive in cache), a loud failure (the bytes dropped at the blob
    /// level), or a MISDECODE — a cache page straddling the floor re-fetches with its pruned
    /// prefix zeroed, and a zeroed varint length of 0 fabricates an empty item wherever the
    /// codec accepts one. Consumers must never read below their own tracked pruning boundary.
    pub async fn snapshot(&mut self) -> Result<Reader<'static, E, V>, Error> {
        Ok(Reader {
            data: Blob::Sealed(self.data.snapshot().await.map_err(Error::Runtime)?),
            bounds: self.bounds.clone(),
            start_offset: self.data.floor(),
            offsets: self.offsets.snapshot().await?,
            codec_config: self.codec_config.clone(),
            compressed: self.compression.is_some(),
            metrics: self.metrics.clone(),
        })
    }

    /// A reader borrowing the journal's live state.
    fn reader(&self) -> Reader<'_, E, V> {
        Reader {
            data: Blob::Writer(&self.data),
            bounds: self.bounds.clone(),
            start_offset: self.data.floor(),
            offsets: self.offsets.reader(),
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

    /// Prune items at positions below `min_position` (capped to the journal's size), exactly:
    /// the new pruning boundary IS the requested position. Returns true if the boundary
    /// advanced.
    ///
    /// Readers holding earlier snapshots and reading newly pruned positions see one of THREE
    /// outcomes: a stale success (the bytes survive in cache), a loud failure (the bytes
    /// dropped at the blob level), or a MISDECODE — a cache page straddling the floor
    /// re-fetches with its pruned prefix zeroed, and a zeroed varint length of 0 fabricates
    /// an empty item wherever the codec accepts one. Consumers must never read below their
    /// own tracked pruning boundary. Positions at or above the new boundary stay readable
    /// everywhere.
    ///
    /// Both blobs' dirty bytes and their new floors land in ONE commit. The floors are
    /// mutations whose durability follows that commit: a crash beforehand regresses them
    /// (never the reverse) and init reconciles (see the module docs).
    pub async fn prune(&mut self, min_position: u64) -> Result<bool, Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        if !self.prune_into(min_position, &mut batch).await? {
            return Ok(false);
        }
        batch.apply_sync().await.map_err(Error::Runtime)?;
        Ok(true)
    }

    /// Stage a prune with `batch`: the caller applies the batch. Returns true if the boundary
    /// advanced.
    ///
    /// Both blobs' buffered bytes are flushed and their native prunes run immediately (the
    /// prune target may be justified by an appended-but-unflushed item, e.g. a consumer's
    /// commit record); the batch then stages both blobs' durability so the floors and data
    /// commit together, data before offsets (see the module docs on staging order).
    ///
    /// # Caller contract
    ///
    /// `batch` must not already stage over either of this journal's blobs: the native prunes
    /// require them to have no open batch (writer exclusivity), so this must be the batch's
    /// first touch of the journal. Call it before [Self::sync_into] when both join one batch.
    pub(crate) async fn prune_into(
        &mut self,
        min_position: u64,
        batch: &mut E::Batch,
    ) -> Result<bool, Error> {
        // Cap to the journal's size.
        let min = min_position.min(self.bounds.end);
        if min <= self.bounds.start {
            return Ok(false);
        }

        // The byte where item `min`'s frame begins: its predecessor's recorded end. `min` is
        // strictly above the boundary, so the predecessor's entry is retained.
        let offset = self.offsets.read(min - 1).await?;

        // Prune the data blob FIRST (both the native mutation and the staged sync): the
        // reconcilable crash direction is data-ahead-of-offsets, never the reverse.
        self.data.prune(offset).await.map_err(Error::Runtime)?;
        self.data.sync_into(batch).await.map_err(Error::Runtime)?;
        self.dirty = false;

        let pruned = self.offsets.prune_into(min, batch).await?;
        debug_assert!(pruned, "the offsets boundary strictly advances");
        self.bounds.start = min;

        self.metrics.update(self.bounds.end, self.bounds.start);

        Ok(true)
    }

    /// Stage the durability of the data blob and the offsets journal with `batch`: the whole
    /// batch commits atomically, so no crash can separate data from offsets. Data is staged
    /// before offsets so even a sequentially replayed batch (the test-only mock fallback)
    /// keeps durable entries at or behind the durable data bytes they index.
    pub(crate) async fn sync_into(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        if self.dirty {
            self.data.sync_into(batch).await.map_err(Error::Runtime)?;
            self.dirty = false;
        }
        self.offsets.sync_into(batch).await
    }

    /// The storage context the journal operates on.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) const fn context(&self) -> &E {
        &self.context
    }

    /// Durably persist the journal: the data blob and the offsets journal, one batch, one
    /// commit.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.sync_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// Remove any persisted data created by the journal.
    ///
    /// This destroys both the data blob and the offsets journal: both partitions' removals
    /// land in ONE atomic commit, so destruction is all-or-nothing.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch);
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: every partition removal lands when the caller
    /// applies the batch with `apply_sync`, atomically with everything else it stages.
    pub(crate) fn destroy_into(self, batch: &mut E::Batch) {
        drop(self.data);
        batch.remove(&self.data_partition, None);
        self.offsets.destroy_into(batch);
    }

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused. After clearing, the
    /// journal will behave as if initialized with `init_at_size(new_size)`.
    ///
    /// # Crash Safety
    ///
    /// The cleared image is durable when this call returns. A crash during the call recovers
    /// the journal in its prior state or with bounds `new_size..new_size` — except when
    /// `new_size` precedes the offsets journal's pruning boundary, which forces both
    /// partitions to be removed and recreated, and a crash between those two commits recovers
    /// an EMPTY journal at position 0 (see the module docs on clearing).
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn clear_to_size(&mut self, new_size: u64) -> Result<(), Error> {
        // A journal sized at `u64::MAX` can never accept an append, and the offsets journal
        // materializes at `new_size` entries, so the target must be byte-representable there.
        // Both are checked before any mutation (the below-boundary path removes state that a
        // later failure could not restore).
        if new_size == u64::MAX {
            return Err(Error::SizeOverflow);
        }
        new_size
            .checked_mul(fixed::Journal::<E, u64>::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        if new_size >= self.offsets.pruning_boundary() {
            // In place: the data blob truncates to its floor (empty, byte coordinates
            // preserved) and the offsets journal materializes its fully pruned image; ONE
            // commit lands both, so a crash recovers the prior state or the cleared one.
            let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
            let floor = self.data.floor();
            self.data
                .resize_into(floor, &mut batch)
                .await
                .map_err(Error::Runtime)?;
            self.offsets.stage_clear(new_size, &mut batch).await?;
            batch.apply_sync().await.map_err(Error::Runtime)?;
            self.offsets.finish_clear(new_size).await?;
        } else {
            // Clearing below the offsets journal's pruning boundary cannot reuse its blob
            // (nothing may shrink below a floor): ONE commit removes BOTH partitions
            // together, a second commits the recreated image. A crash between them recovers
            // an EMPTY journal at position 0 — both sides restart together, so the
            // intermediate state is consistent and never fabricates items.
            self.data.wait_for_sync().await.map_err(Error::Runtime)?;
            let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
            self.offsets.stage_remove(&mut batch).await?;
            batch.remove(&self.data_partition, None);
            batch.apply_sync().await.map_err(Error::Runtime)?;

            let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
            self.offsets.finish_recreate(new_size, &mut batch).await?;
            let (raw, size) = self
                .context
                .open(&self.data_partition, BLOB_NAME)
                .await
                .map_err(Error::Runtime)?;
            assert_eq!(size, 0, "the applied removal emptied the partition");
            batch.sync(&raw);
            self.data = Writer::new(raw, 0, self.write_buffer.get(), self.page_cache.clone())
                .await
                .map_err(Error::Runtime)?;
            batch.apply_sync().await.map_err(Error::Runtime)?;
        }

        self.bounds = new_size..new_size;
        self.dirty = false;
        self.metrics.update(self.bounds.end, self.bounds.start);
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
        let state = reader.replay_state(start_pos, buffer).await?;

        Ok(super::replay_stream(state))
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

    fn context(&self) -> &E {
        Self::context(self)
    }

    async fn sync_into(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        Self::sync_into(self, batch).await
    }

    async fn prune_into(&mut self, min_position: u64, batch: &mut E::Batch) -> Result<bool, Error> {
        Self::prune_into(self, min_position, batch).await
    }

    fn destroy_into(self, batch: &mut E::Batch) {
        Self::destroy_into(self, batch);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::tests::run_contiguous_tests;
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic, Batchable as _, BufferPooler, Metrics as _, Runner, Spawner as _, Storage,
        Supervisor as _,
    };
    use commonware_utils::{sequence::FixedBytes, NZUsize, NZU16};
    use futures::{FutureExt as _, StreamExt as _};
    use std::num::NonZeroU16;

    // Use some jank sizes to exercise boundary conditions.
    const PAGE_SIZE: NonZeroU16 = NZU16!(101);
    // Larger page sizes for tests that need more buffer space.
    const LARGE_PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const SMALL_PAGE_SIZE: NonZeroU16 = NZU16!(512);

    /// The largest position the offsets journal can represent in bytes.
    const MAX_POSITION: u64 = u64::MAX / 8;

    /// Extract a metric counter's value from encoded metrics output.
    fn counter(buffer: &str, name: &str) -> u64 {
        buffer
            .lines()
            .find(|l| l.contains(name) && !l.starts_with('#'))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .expect("counter missing")
    }

    fn test_cfg(
        pooler: &impl BufferPooler,
        partition: &str,
        page_size: NonZeroU16,
        pages: usize,
    ) -> Config<()> {
        Config {
            partition: partition.into(),
            compression: None,
            codec_config: (),
            page_cache: CacheRef::from_pooler(pooler, page_size, NZUsize!(pages)),
            write_buffer: NZUsize!(1024),
        }
    }

    /// The generic suite over the variable journal.
    #[test_traced]
    fn test_variable_journal_contiguous_suite() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            run_contiguous_tests(move |test_name: String, idx: usize| {
                let label = test_name.replace('-', "_");
                let context = context
                    .child("test")
                    .with_attribute("name", &label)
                    .with_attribute("index", idx);
                async move {
                    let cfg =
                        test_cfg(&context, &format!("suite-{test_name}"), LARGE_PAGE_SIZE, 10);
                    Journal::<_, u64>::init(context, cfg).await
                }
                .boxed()
            })
            .await;
        });
    }

    #[test_traced]
    fn test_variable_append_many_compressed() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                compression: Some(1),
                ..test_cfg(&context, "append-many-compressed", SMALL_PAGE_SIZE, 2)
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
    fn test_variable_append_many_exceeding_write_buffer_reopens() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = Config {
                write_buffer: NZUsize!(512),
                ..test_cfg(&context, "append-many-exceeds-buffer", SMALL_PAGE_SIZE, 2)
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

    /// A journal sized at u64::MAX (or beyond the offsets journal's byte representability) is
    /// rejected before any mutation.
    #[test_traced]
    fn test_variable_init_at_size_overflow_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-at-max", SMALL_PAGE_SIZE, 2);

            assert!(matches!(
                Journal::<_, u64>::init_at_size(context.child("max"), cfg.clone(), u64::MAX).await,
                Err(Error::SizeOverflow)
            ));
            assert!(matches!(
                Journal::<_, u64>::init_at_size(context.child("over"), cfg, MAX_POSITION + 1).await,
                Err(Error::OffsetOverflow)
            ));
        });
    }

    #[test_traced]
    fn test_variable_try_read_many_sync_matches_read_many() {
        // Cached positions are served synchronously and match the async batched read.
        // Positions that fail validation are misses rather than errors.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "read-many-sync", LARGE_PAGE_SIZE, 64);
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

            // An out-of-range position is a miss, not an error, and does not poison the rest
            // of the batch.
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
            let cfg = test_cfg(&context, "read-many-unsorted", SMALL_PAGE_SIZE, 2);
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
            let cfg = test_cfg(&context, "read-many-duplicate", SMALL_PAGE_SIZE, 2);
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
            let cfg = test_cfg(&context, "read-many-probe-complete", SMALL_PAGE_SIZE, 2);
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

    /// Completing a probe miss whose frame start was already resolved must not consult the
    /// offsets journal again.
    #[test_traced]
    fn test_variable_fetch_misses_reuses_resolved_offset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "fetch-miss-offset-reuse", SMALL_PAGE_SIZE, 4);
            let appended = (0..40)
                .map(|i| FixedBytes::new([i as u8; 300]))
                .collect::<Vec<_>>();
            let mut journal = Journal::<_, FixedBytes<300>>::init(context.child("j"), cfg)
                .await
                .unwrap();
            journal.append_many(Many::Flat(&appended)).await.unwrap();
            journal.sync().await.unwrap();
            let reader = journal.snapshot().await.unwrap();

            // Present a miss carrying its frame start: the completion must serve it from the
            // data blob alone (offsets counters unchanged).
            let offset = reader.frame_start(5).await.unwrap();
            let before = context.encode();
            let items = reader
                .fetch_misses(&[Miss {
                    position: 5,
                    offset: Some(offset),
                }])
                .await
                .unwrap();
            assert_eq!(items, vec![appended[5].clone()]);
            let after = context.encode();
            assert_eq!(
                counter(&after, "offsets_items_read_total"),
                counter(&before, "offsets_items_read_total")
            );
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_read_many_consecutive_after_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(
                &context,
                "read-many-consecutive-after-reopen",
                SMALL_PAGE_SIZE,
                2,
            );

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
    fn test_variable_read_many_scattered_runs() {
        // Read a batch where cache hits are interleaved with non-consecutive misses. The misses
        // split into runs that are fetched separately, and each run's items must land in the
        // correct result slots between the cached items. Every item's payload encodes its
        // position, so a wrong run boundary or a misplaced result fails the value assertions.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "read-many-scattered-runs", SMALL_PAGE_SIZE, 16);

            // Each item's frame is 302 bytes, so full pages go cold on reopen with a fresh
            // page cache, which is what lets this test stage misses at all.
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

            // Reopen with a fresh page cache so full pages are cold, then warm two islands.
            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(16)),
                ..cfg
            };
            let mut journal = Journal::<_, FixedBytes<300>>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.snapshot().await.unwrap();
            reader.read(6).await.unwrap();
            reader.read(16).await.unwrap();

            // Derive the hit/miss split the batch will see (read_many's sync pass is exactly
            // this probe), then check the batch's values and accounting against it.
            let positions = [0, 3, 5, 6, 10, 12, 15, 17, 20, 21, 23];
            let served = reader.try_read_many_sync(&positions);
            let hits = served.iter().filter(|item| item.is_some()).count() as u64;
            let misses = positions.len() as u64 - hits;
            assert!(misses > 0, "some positions must be cold");
            assert!(hits > 0, "some positions must be warm");

            let expected: Vec<_> = positions
                .iter()
                .map(|&p| items[p as usize].clone())
                .collect();
            let before = context.encode();
            assert_eq!(reader.read_many(&positions).await.unwrap(), expected);
            let after = context.encode();
            assert_eq!(
                counter(&after, "second_cache_hits") - counter(&before, "second_cache_hits"),
                hits
            );
            assert_eq!(
                counter(&after, "second_cache_misses") - counter(&before, "second_cache_misses"),
                misses
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

    #[test_traced]
    fn test_variable_replay() {
        const ITEMS: u64 = 703;
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "replay", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0u64..ITEMS {
                let pos = journal.append(&(i * 3)).await.unwrap();
                assert_eq!(pos, i);
            }

            // Replay should return all items.
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(0, NZUsize!(1024)).await.unwrap();
                let mut count = 0u64;
                futures::pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(pos * 3, item, "pos={pos}");
                    count += 1;
                }
                assert_eq!(count, ITEMS);
            }

            // A partial replay starts mid-journal (mid-page and mid-frame).
            {
                const START_POS: u64 = 53;
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(START_POS, NZUsize!(64)).await.unwrap();
                let mut count = 0;
                futures::pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert!(pos >= START_POS);
                    assert_eq!(pos * 3, item);
                    count += 1;
                }
                assert_eq!(count, ITEMS - START_POS);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_replay_stops_after_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "replay-error", SMALL_PAGE_SIZE, 2);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0u64..300 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen with a fresh page cache so replay must hit storage, then inject read
            // faults: the stream must surface the error once and terminate.
            let cfg = Config {
                page_cache: CacheRef::from_pooler(&context, SMALL_PAGE_SIZE, NZUsize!(2)),
                ..cfg
            };
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.snapshot().await.unwrap();
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                read_rate: Some(1.0),
                ..Default::default()
            };
            let stream = reader.replay(0, NZUsize!(1024)).await.unwrap();
            futures::pin_mut!(stream);

            assert!(matches!(
                stream.next().await.unwrap(),
                Err(Error::Runtime(_))
            ));
            assert!(stream.next().await.is_none());

            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            journal.destroy().await.unwrap();
        });
    }

    /// Pruning is exact at every step, and everything stays readable at or above the boundary.
    #[test_traced]
    fn test_variable_multiple_sequential_prunes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "sequential-prunes", LARGE_PAGE_SIZE, 10);
            let mut journal = Journal::<_, u64>::init(context, cfg).await.unwrap();

            for i in 0..40u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            assert_eq!(journal.bounds(), 0..40);

            for boundary in [7u64, 19, 33] {
                assert!(journal.prune(boundary).await.unwrap());
                assert_eq!(journal.bounds(), boundary..40);
                assert!(matches!(
                    journal.read(boundary - 1).await,
                    Err(Error::ItemPruned(_))
                ));
                assert_eq!(journal.read(boundary).await.unwrap(), boundary * 100);
                assert_eq!(journal.read(39).await.unwrap(), 3900);
            }

            // Size is unaffected by pruning.
            assert_eq!(journal.size(), 40);

            journal.destroy().await.unwrap();
        });
    }

    /// Test that pruning all data and re-initializing preserves positions.
    #[test_traced]
    fn test_variable_prune_all_then_reinit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "prune-all-reinit", LARGE_PAGE_SIZE, 10);

            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..100u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            let pruned = journal.prune(100).await.unwrap();
            assert!(pruned);
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert!(bounds.is_empty());
            assert!(matches!(journal.read(99).await, Err(Error::ItemPruned(99))));

            journal.sync().await.unwrap();
            drop(journal);

            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 100);
            assert!(bounds.is_empty());

            // Next append should get position 100.
            journal.append(&10000).await.unwrap();
            assert_eq!(journal.bounds(), 100..101);
            assert_eq!(journal.read(100).await.unwrap(), 10000);
            assert!(matches!(journal.read(99).await, Err(Error::ItemPruned(99))));

            journal.destroy().await.unwrap();
        });
    }

    /// The directed boundary test: prune mid-journal, the boundary is exact and persists
    /// across a restart once synced; an unsynced prune regresses across a crash and can be
    /// re-applied.
    #[test_traced]
    fn test_variable_prune_boundary_persistence_and_regression() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "prune-regression", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..200u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();

            // A committed prune to an arbitrary position: the boundary is exact.
            assert!(journal.prune(37).await.unwrap());
            assert_eq!(journal.bounds(), 37..200);

            // Stage a further prune whose commit never lands: the floors advance in RAM but
            // the crash below discards them.
            let mut batch = journal.context().batch().await.unwrap();
            assert!(journal.prune_into(150, &mut batch).await.unwrap());
            assert_eq!(journal.bounds(), 150..200);
            drop(batch);
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "prune-regression", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // The unsynced prune regressed to the last committed boundary.
            assert_eq!(journal.bounds(), 37..200);
            assert_eq!(journal.read(37).await.unwrap(), 37);

            // Re-pruning after the regression works and is exact.
            assert!(journal.prune(150).await.unwrap());
            assert_eq!(journal.bounds(), 150..200);
            assert!(matches!(
                journal.read(149).await,
                Err(Error::ItemPruned(149))
            ));
            assert_eq!(journal.read(150).await.unwrap(), 150);

            journal.destroy().await.unwrap();
        });
    }

    /// The directed reconciliation test: a commit adopts the DATA blob's pruned floor between
    /// the two prunes inside `prune_into`, then a crash discards the offsets journal's floor.
    /// Init must treat the more advanced data floor as authoritative and re-prune the laggard
    /// offsets journal to the exact boundary.
    #[test_traced]
    fn test_variable_crash_between_data_and_offsets_prune() {
        const MIN: u64 = 63;
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "prune-crash-window", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..100u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Plant the adopted (data-ahead, offsets-behind) state: prune ONLY the data blob
            // to MIN's frame start and commit it, exactly what a commit landing between the
            // two native prunes inside `prune_into` adopts. The crash below then discards
            // everything after that commit.
            let offset = journal.offsets.read(MIN - 1).await.unwrap();
            journal.data.prune(offset).await.unwrap();
            journal.data.sync().await.unwrap();
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "prune-crash-window", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Init reconciled: the data floor named the boundary and the offsets journal was
            // re-pruned to it.
            assert_eq!(journal.bounds(), MIN..100);
            assert_eq!(journal.offsets.pruning_boundary(), MIN);
            assert!(matches!(
                journal.read(MIN - 1).await,
                Err(Error::ItemPruned(_))
            ));
            for i in MIN..100 {
                assert_eq!(journal.read(i).await.unwrap(), i);
            }

            // The reconciled image is durable: a plain reopen agrees.
            journal.sync().await.unwrap();
            drop(journal);
            let journal = Journal::<_, u64>::init(context.child("third"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), MIN..100);

            journal.destroy().await.unwrap();
        });
    }

    /// Reconciliation at the far edge: the data blob's floor advanced past EVERY retained
    /// entry (a full prune whose offsets side never committed). Init empties the journal at
    /// its size.
    #[test_traced]
    fn test_variable_crash_data_fully_pruned_offsets_not() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "prune-crash-full", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..50u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();

            let offset = journal.offsets.read(49).await.unwrap();
            journal.data.prune(offset).await.unwrap();
            journal.data.sync().await.unwrap();
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "prune-crash-full", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds, 50..50);
            assert!(bounds.is_empty());

            // Appends continue from the recovered size.
            assert_eq!(journal.append(&50).await.unwrap(), 50);
            assert_eq!(journal.read(50).await.unwrap(), 50);

            journal.destroy().await.unwrap();
        });
    }

    /// A data floor that falls inside a frame is not a state any prune produces: corruption.
    #[test_traced]
    fn test_variable_data_floor_mid_frame_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "floor-mid-frame", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune the data blob to one byte short of a frame boundary and commit it.
            let offset = journal.offsets.read(9).await.unwrap();
            journal.data.prune(offset - 1).await.unwrap();
            journal.data.sync().await.unwrap();
            drop(journal);

            let result = Journal::<_, u64>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// An unsynced append is discarded by a crash while synced items survive, and the journal
    /// recovers cleanly (both blobs regress to the same commit).
    #[test_traced]
    fn test_variable_crash_discards_unsynced_appends() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "crash-unsynced", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();
            for i in 10u64..20 {
                journal.append(&i).await.unwrap();
            }
            // No sync for the second half.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "crash-unsynced", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 10);
            for i in 0u64..10 {
                assert_eq!(journal.read(i).await.unwrap(), i);
            }
            // Appends continue from the recovered size.
            let pos = journal.append(&10).await.unwrap();
            assert_eq!(pos, 10);
            journal.destroy().await.unwrap();
        });
    }

    /// Trailing data bytes past the last offsets entry are corruption.
    #[test_traced]
    fn test_variable_trailing_data_garbage_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "trailing-garbage", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                journal.append(&7).await.unwrap();
                journal.sync().await.unwrap();
            }

            let (blob, size) = context
                .open("trailing-garbage_data", super::BLOB_NAME)
                .await
                .unwrap();
            blob.write_at_sync(size, vec![0u8; 3]).await.unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A data blob shorter than the last offsets entry is corruption.
    #[test_traced]
    fn test_variable_short_data_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "short-data", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..5u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            let (blob, size) = context
                .open("short-data_data", super::BLOB_NAME)
                .await
                .unwrap();
            blob.resize(size - 1).await.unwrap();
            blob.sync().await.unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Data bytes with no offsets journal at all (e.g. the offsets partition was lost) are
    /// corruption, not silently re-indexed.
    #[test_traced]
    fn test_variable_offsets_partition_loss_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "offsets-loss", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..5u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            context.remove("offsets-loss_offsets", None).await.unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A partial (non-multiple-of-8) offsets blob is corruption, surfaced by the offsets
    /// journal's own init.
    #[test_traced]
    fn test_variable_partial_offsets_entry_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "partial-offsets", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..5u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            let (blob, size) = context
                .open("partial-offsets_offsets", b"journal")
                .await
                .unwrap();
            blob.write_at_sync(size, vec![0u8; 4]).await.unwrap();

            let result = Journal::<_, u64>::init(context.child("second"), cfg).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_variable_rewind_sync_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "rewind-reopen", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..25u64 {
                journal.append(&(i * 10)).await.unwrap();
            }

            // Rewind mid-journal, then append: positions continue from the rewind point.
            journal.rewind(20).await.unwrap();
            assert_eq!(journal.size(), 20);
            let pos = journal.append(&12345).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), 12345);

            // Rewind again and reopen: the rewind is durable at return, no sync needed.
            journal.rewind(5).await.unwrap();
            drop(journal);
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 5);
            for i in 0u64..5 {
                assert_eq!(journal.read(i).await.unwrap(), i * 10);
            }

            journal.destroy().await.unwrap();
        });
    }

    /// A rewind is durable and atomic when it returns: a crash right after recovers the
    /// rewound journal (both blobs truncated together).
    #[test_traced]
    fn test_variable_rewind_durable_across_crash() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "rewind-crash", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..10u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.rewind(4).await.unwrap();
            // No sync: rewind itself must have committed the truncations.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "rewind-crash", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 4);
            for i in 0u64..4 {
                assert_eq!(journal.read(i).await.unwrap(), i);
            }
            let pos = journal.append(&100).await.unwrap();
            assert_eq!(pos, 4);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_init_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-at-size", SMALL_PAGE_SIZE, 4);

            // Init at an arbitrary position: empty, and the next append lands there.
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 37)
                    .await
                    .unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 37);
            assert!(matches!(journal.read(36).await, Err(Error::ItemPruned(36))));

            let pos = journal.append(&37).await.unwrap();
            assert_eq!(pos, 37);
            assert_eq!(journal.read(37).await.unwrap(), 37);
            journal.sync().await.unwrap();
            drop(journal);

            // The cleared image persists across a plain reopen.
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 37..38);
            assert_eq!(journal.read(37).await.unwrap(), 37);
            drop(journal);

            // Re-initializing at a LOWER size than the boundary recreates both partitions.
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("third"), cfg.clone(), 7)
                    .await
                    .unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 7);
            let pos = journal.append(&7).await.unwrap();
            assert_eq!(pos, 7);
            journal.destroy().await.unwrap();

            // Init at size zero behaves like a fresh journal.
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("fourth"), cfg.clone(), 0)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            let pos = journal.append(&0).await.unwrap();
            assert_eq!(pos, 0);
            journal.destroy().await.unwrap();
        });
    }

    /// The cleared image persists across a reopen even when nothing is ever appended.
    #[test_traced]
    fn test_variable_init_at_size_persists_without_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-at-size-empty", SMALL_PAGE_SIZE, 4);
            {
                let journal =
                    Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 53)
                        .await
                        .unwrap();
                assert_eq!(journal.bounds(), 53..53);
            }
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 53..53);
            journal.destroy().await.unwrap();
        });
    }

    /// The cleared image is durable when `init_at_size` returns: a crash immediately after
    /// recovers the cleared journal.
    #[test_traced]
    fn test_variable_init_at_size_durable_without_sync() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "init-at-size-crash", SMALL_PAGE_SIZE, 4);
            let journal = Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 53)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 53..53);
            // No sync: init_at_size itself must have committed the image.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "init-at-size-crash", SMALL_PAGE_SIZE, 4);
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 53..53);
            journal.destroy().await.unwrap();
        });
    }

    /// init_at_size discards existing data wholesale.
    #[test_traced]
    fn test_variable_init_at_size_clears_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-at-size-clears", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..25u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("second"), cfg.clone(), 100)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 100..100);
            for i in [0u64, 24, 99] {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }
            let pos = journal.append(&100).await.unwrap();
            assert_eq!(pos, 100);
            assert_eq!(journal.read(100).await.unwrap(), 100);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_init_at_size_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-at-size-prune", SMALL_PAGE_SIZE, 4);
            let mut journal =
                Journal::<_, u64>::init_at_size(context.child("first"), cfg.clone(), 100)
                    .await
                    .unwrap();

            for i in 100u64..120 {
                let pos = journal.append(&i).await.unwrap();
                assert_eq!(pos, i);
            }

            // Prune within the appended range: exact boundary.
            assert!(journal.prune(110).await.unwrap());
            assert_eq!(journal.bounds(), 110..120);
            assert!(matches!(
                journal.read(109).await,
                Err(Error::ItemPruned(109))
            ));
            assert_eq!(journal.read(110).await.unwrap(), 110);

            // Replay from the boundary.
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(110, NZUsize!(1024)).await.unwrap();
                futures::pin_mut!(stream);
                let mut count = 0;
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(pos, item);
                    count += 1;
                }
                assert_eq!(count, 10);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_clear_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "clear-test", LARGE_PAGE_SIZE, 10);
            let mut journal = Journal::<_, u64>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            for i in 0..25u64 {
                journal.append(&(i * 100)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Clear forward: in-place, resetting the journal to an empty image at 100.
            journal.clear_to_size(100).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds, 100..100);
            for i in 0..25 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            // The cleared size persists across a restart without any appends.
            drop(journal);
            let mut journal =
                Journal::<_, u64>::init(context.child("journal_after_clear"), cfg.clone())
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 100..100);

            // Append new data starting at position 100.
            for i in 100..105u64 {
                let pos = journal.append(&(i * 100)).await.unwrap();
                assert_eq!(pos, i);
            }
            assert_eq!(journal.bounds(), 100..105);
            for i in 100..105u64 {
                assert_eq!(journal.read(i).await.unwrap(), i * 100);
            }
            journal.sync().await.unwrap();

            // Prune, then clear BELOW the boundary: both partitions are recreated.
            journal.prune(103).await.unwrap();
            assert_eq!(journal.bounds(), 103..105);
            journal.clear_to_size(3).await.unwrap();
            assert_eq!(journal.bounds(), 3..3);
            let pos = journal.append(&333).await.unwrap();
            assert_eq!(pos, 3);
            journal.sync().await.unwrap();
            drop(journal);

            // All of it persists across a reopen.
            let mut journal = Journal::<_, u64>::init(context.child("journal_reopened"), cfg)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..4);
            assert_eq!(journal.read(3).await.unwrap(), 333);

            // Clearing to u64::MAX is rejected.
            assert!(matches!(
                journal.clear_to_size(u64::MAX).await,
                Err(Error::SizeOverflow)
            ));

            journal.destroy().await.unwrap();
        });
    }

    /// The cleared image (both clear paths) is durable when `clear_to_size` returns.
    #[test_traced]
    fn test_variable_clear_to_size_durable_without_sync() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, "clear-crash", SMALL_PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..10u64 {
                journal.append(&i).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.prune(8).await.unwrap();

            // In-place clear (target above the boundary), then a below-boundary clear.
            journal.clear_to_size(20).await.unwrap();
            assert_eq!(journal.bounds(), 20..20);
            journal.clear_to_size(5).await.unwrap();
            assert_eq!(journal.bounds(), 5..5);
            // No sync: the crash below must still recover the cleared journal.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context, "clear-crash", SMALL_PAGE_SIZE, 4);
            let journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 5..5);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_sync_no_existing_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-sync-fresh", SMALL_PAGE_SIZE, 4);

            // Fresh journal with range starting at zero: nothing to do.
            let journal = Journal::<_, u64>::init_sync(context.child("zero"), cfg.clone(), 0..10)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            journal.destroy().await.unwrap();

            // Fresh journal with a nonzero range start: cleared to the start.
            let mut journal =
                Journal::<_, u64>::init_sync(context.child("five"), cfg.clone(), 5..10)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 5..5);
            assert_eq!(journal.append(&5).await.unwrap(), 5);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_sync_existing_data_overlap() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-sync-overlap", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("seed"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..8u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            // Overlapping range: retained data is pruned exactly to the range start.
            let mut journal =
                Journal::<_, u64>::init_sync(context.child("sync"), cfg.clone(), 3..20)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 3..8);
            for i in 3..8u64 {
                assert_eq!(journal.read(i).await.unwrap(), i);
            }
            assert!(matches!(journal.read(2).await, Err(Error::ItemPruned(2))));
            assert_eq!(journal.append(&8).await.unwrap(), 8);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    #[should_panic(expected = "range must not be empty")]
    fn test_init_sync_rejects_empty_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-sync-empty-range", SMALL_PAGE_SIZE, 4);
            let _ = Journal::<_, u64>::init_sync(context, cfg, 5..5).await;
        });
    }

    #[test_traced]
    fn test_init_sync_existing_data_exact_match_and_beyond() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-sync-exact", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("seed"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..10u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            // Existing size == range.end is accepted.
            let journal = Journal::<_, u64>::init_sync(context.child("exact"), cfg.clone(), 4..10)
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 4..10);
            drop(journal);

            // Existing data beyond range.end is rejected.
            let result =
                Journal::<_, u64>::init_sync(context.child("beyond"), cfg.clone(), 4..9).await;
            assert!(matches!(result, Err(Error::ItemOutOfRange(10))));

            // Clean up through a plain init.
            let journal = Journal::<_, u64>::init(context.child("cleanup"), cfg)
                .await
                .unwrap();
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_init_sync_existing_data_stale() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-sync-stale", SMALL_PAGE_SIZE, 4);
            {
                let mut journal = Journal::<_, u64>::init(context.child("seed"), cfg.clone())
                    .await
                    .unwrap();
                for i in 0..5u64 {
                    journal.append(&i).await.unwrap();
                }
                journal.sync().await.unwrap();
            }

            // All existing data precedes the range: reset to the range start.
            let mut journal =
                Journal::<_, u64>::init_sync(context.child("sync"), cfg.clone(), 10..20)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 10..10);
            assert_eq!(journal.append(&10).await.unwrap(), 10);

            journal.destroy().await.unwrap();
        });
    }

    /// A stale empty journal ahead of the requested range start (even beyond the range end,
    /// e.g. after a crashed clear_to_size) is re-cleared to the range start.
    #[test_traced]
    fn test_init_sync_stale_empty_position() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "init-sync-stale-empty", SMALL_PAGE_SIZE, 4);
            {
                let journal =
                    Journal::<_, u64>::init_at_size(context.child("seed"), cfg.clone(), 30)
                        .await
                        .unwrap();
                assert_eq!(journal.bounds(), 30..30);
            }

            let mut journal =
                Journal::<_, u64>::init_sync(context.child("sync"), cfg.clone(), 7..20)
                    .await
                    .unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 7);
            assert_eq!(journal.append(&7).await.unwrap(), 7);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_variable_journal_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "metrics", PAGE_SIZE, 10);
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
                "variable_metrics_sync_calls_total 1",
                "variable_metrics_append_duration_count 1",
                "variable_metrics_append_many_duration_count 1",
                "variable_metrics_read_duration_count 0",
                "variable_metrics_read_many_duration_count 1",
                "variable_metrics_sync_duration_count 1",
                "variable_metrics_cache_hits_total 4",
                "variable_metrics_cache_misses_total 0",
                "variable_metrics_offsets_size 4",
                "variable_metrics_offsets_pruning_boundary 2",
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
            let cfg = test_cfg(&context, "miss", PAGE_SIZE, 10);
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

    /// Snapshots freeze their bounds: appends and rewinds after the snapshot do not move it,
    /// and unpruned positions stay readable.
    #[test_traced]
    fn test_variable_snapshot_frozen_across_appends() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "snapshot-frozen", LARGE_PAGE_SIZE, 10);
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            let snapshot = journal.snapshot().await.unwrap();
            assert_eq!(snapshot.bounds(), 0..20);

            // Concurrent appends are invisible to the snapshot.
            for i in 20u64..40 {
                journal.append(&(i * 100)).await.unwrap();
            }
            assert_eq!(snapshot.bounds(), 0..20);
            assert!(matches!(
                snapshot.read(20).await,
                Err(Error::ItemOutOfRange(20))
            ));
            for i in 0u64..20 {
                assert_eq!(snapshot.read(i).await.unwrap(), i * 100);
            }

            // A prune below the snapshot's range freezes the snapshot's BOUNDS, but the
            // pruned bytes are gone at the blob level: only unpruned positions are guaranteed
            // readable through the snapshot.
            journal.prune(10).await.unwrap();
            assert_eq!(snapshot.bounds(), 0..20);
            for i in 10u64..20 {
                assert_eq!(snapshot.read(i).await.unwrap(), i * 100);
            }

            let fresh = journal.snapshot().await.unwrap();
            assert_eq!(fresh.bounds(), 10..40);
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
            let cfg = test_cfg(&context, "snapshot-concurrent", LARGE_PAGE_SIZE, 10);
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

    /// Replay through a stale snapshot observes the snapshot's frozen bounds.
    #[test_traced]
    fn test_variable_replay_from_stale_snapshot() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "snapshot-replay", LARGE_PAGE_SIZE, 10);
            let mut journal = Journal::<_, u64>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&(i * 100)).await.unwrap();
            }

            let snapshot = journal.snapshot().await.unwrap();
            for i in 7u64..20 {
                journal.append(&(i * 100)).await.unwrap();
            }

            {
                let stream = snapshot.replay(0, NZUsize!(1024)).await.unwrap();
                futures::pin_mut!(stream);
                let mut count = 0u64;
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(item, pos * 100);
                    count += 1;
                }
                assert_eq!(count, 7);
            }
            drop(snapshot);

            journal.destroy().await.unwrap();
        });
    }

    /// Interleave appends, exact prunes, and syncs over many cycles, then reopen: both blobs'
    /// committed state must recover cleanly whatever the floors' page phase.
    #[test_traced]
    fn test_variable_many_prune_sync_cycles_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "prune-cycles", PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            let mut appended = 0u64;
            for i in 0..100u64 {
                for _ in 0..19 {
                    journal.append(&appended).await.unwrap();
                    appended += 1;
                }
                journal.prune((i * 19).min(appended)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let mut journal = Journal::<_, u64>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 99 * 19..100 * 19);

            // Fully prune, append into the floor's page, and sync: the next reopen must
            // still verify and reconcile cleanly.
            journal.prune(appended).await.unwrap();
            assert!(journal.bounds().is_empty());
            for _ in 0..3 {
                journal.append(&appended).await.unwrap();
                appended += 1;
            }
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, u64>::init(context.child("third"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 100 * 19..100 * 19 + 3);
            journal.destroy().await.unwrap();
        });
    }

    /// Append many across page boundaries in one call, including the nested shape and
    /// prepared appends.
    #[test_traced]
    fn test_variable_append_many_shapes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, "append-shapes", PAGE_SIZE, 4);
            let mut journal = Journal::<_, u64>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            let first: Vec<u64> = (0u64..75).collect();
            let second: Vec<u64> = (75u64..100).collect();
            let pos = journal
                .append_many(Many::Nested(&[&first, &second]))
                .await
                .unwrap();
            assert_eq!(pos, 99);

            // Prepared appends land identically.
            let third: Vec<u64> = (100u64..110).collect();
            let prepared = journal.prepare_append(Many::Flat(&third)).unwrap();
            let pos = journal.append_prepared(prepared).await.unwrap();
            assert_eq!(pos, 109);

            for i in 0u64..110 {
                assert_eq!(journal.read(i).await.unwrap(), i);
            }

            journal.destroy().await.unwrap();
        });
    }
}
