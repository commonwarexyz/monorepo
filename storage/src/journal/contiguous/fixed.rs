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
//! All items live in ONE blob (`b"journal"` in `cfg.partition`), each at the byte offset
//! `position * CHUNK_SIZE` from the blob's origin. Appends land at the blob's size, and
//! page-level caching and write buffering are provided by a buffer pool.
//!
//! ```text
//! +--------+--------+-----+----------+
//! | item_0 | item_1 | ... | item_n-1 |
//! +--------+--------+-----+----------+
//! ```
//!
//! # Pruning
//!
//! `prune` forwards to the runtime's native [commonware_runtime::Blob::prune]: bytes below the
//! requested position's offset drop, exactly. The pruning boundary is derived from the blob
//! alone as `floor / CHUNK_SIZE` (the journal only ever prunes at item multiples, so the
//! floor is always item-aligned). The floor is a mutation, not a durability point: it
//! persists at the journal's next sync, and a crash may regress it to the last synced floor
//! — never the reverse — so consumers re-prune after recovery. Whether regressed-range
//! items hold their original bytes is backend-defined ([`commonware_runtime::Blob::prune`]):
//! the volume resurfaces them, raw file backends may have reclaimed the space, and this
//! journal never reads below its own boundary either way.
//!
//! # Recovery
//!
//! The storage backend restores the blob to exactly its last-synced state after a crash, so
//! recovery is derivation, not repair: the size is the blob's byte length over `CHUNK_SIZE`
//! (a partial item is corruption) and the boundary is the floor over `CHUNK_SIZE`. No
//! auxiliary record exists.
//!
//! # Consistency
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the
//! caller to determine when to force pending data to be durably written using `sync`.
//!
//! # Clearing / reset
//!
//! Clearing wipes all data and restarts the journal at a new size: the blob becomes
//! `new_size * CHUNK_SIZE` bytes of fully pruned prefix (hole-extended, then pruned — both
//! cheap metadata mutations), committed with one sync. A clear at or above the current
//! pruning boundary transforms the blob in place and is all-or-nothing: a crash recovers
//! either the prior state or the cleared one. A clear BELOW the boundary must remove and
//! recreate the blob (nothing may shrink below the floor), so a crash between the removal's
//! commit and the new image's commit recovers an EMPTY journal at position 0 — never
//! fabricated items — and the sync flows that clear backwards re-clear on reopen.
//!
//! Callers reach this through `clear_to_size` (clear an open journal) or `init_at_size` (open
//! straight into a cleared, empty journal at a given size).
//!
//! # Replay
//!
//! The `replay` method supports fast reading of all unpruned items into memory.

use super::Replay as BlobReplay;
#[commonware_macros::stability(ALPHA)]
use crate::{journal::authenticated, merkle};
use crate::{
    journal::{
        contiguous::{metrics::Metrics, Many, Mutable},
        Error,
    },
    Context,
};
use commonware_codec::{CodecFixedShared, DecodeExt as _, ReadExt as _};
use commonware_runtime::{
    buffer::paged::{CacheRef, Writer},
    Blob as RBlob, Buf, IoBuf, WriteBatch as _,
};
use commonware_utils::Cached;
use futures::Stream;
use std::{marker::PhantomData, num::NonZeroUsize, ops::Range, sync::Arc};

/// Name of the single blob holding all items.
const BLOB_NAME: &[u8] = b"journal";

// Reusable scratch for [`Reader::probe_items`], grown to the largest probe served on the
// thread. Probes run per shard on the hot read path, where a fresh zeroed allocation per call
// contends under the pool's fan-out.
commonware_utils::thread_local_cache!(static PROBE_SCRATCH: Vec<u8>);

/// Items encoded for a deferred append, created by [`Journal::prepare_append`] and consumed by
/// [`Journal::append_prepared`].
pub struct PreparedAppend<A> {
    buf: Vec<u8>,
    _marker: PhantomData<A>,
}

/// Build a replay stream over `[start_pos, bounds.end)` of the journal's blob.
///
/// `buffer` is a byte budget for each read batch, not an item count.
fn replay_stream<'a, B: RBlob, A: CodecFixedShared>(
    blob: &'a Writer<B>,
    bounds: Range<u64>,
    start_pos: u64,
    buffer: NonZeroUsize,
) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send + use<'a, B, A>, Error> {
    if start_pos > bounds.end {
        return Err(Error::ItemOutOfRange(start_pos));
    }
    if start_pos < bounds.start {
        return Err(Error::ItemPruned(start_pos));
    }

    let mut state = None;
    if start_pos < bounds.end {
        let offset = start_pos
            .checked_mul(A::SIZE as u64)
            .ok_or(Error::OffsetOverflow)?;
        state = Some(FixedReplayState::<B, A> {
            replay: BlobReplay::new(blob, offset, buffer)?,
            pos: start_pos,
            end_pos: bounds.end,
            items_per_batch: (buffer.get() / A::SIZE).max(1),
            _marker: PhantomData,
        });
    }

    Ok(super::replay_stream(state))
}

/// Replay state over the journal's blob.
struct FixedReplayState<'a, B: RBlob, A> {
    /// Sequential logical bytes for the blob.
    replay: BlobReplay<'a, B>,
    /// Next position to yield.
    pos: u64,
    /// Exclusive end position.
    end_pos: u64,
    /// Maximum number of items decoded per stream poll.
    items_per_batch: usize,
    _marker: PhantomData<A>,
}

impl<B: RBlob, A: CodecFixedShared> super::ReplayBatchState for FixedReplayState<'_, B, A> {
    type Item = A;

    /// Decode the next batch of fixed-size items.
    async fn next_batch(mut self) -> Option<(Vec<Result<(u64, A), Error>>, Self)> {
        if self.pos == self.end_pos {
            return None;
        }

        // Require at least one whole item so a short blob is reported as corruption at the
        // current position. Additional already-buffered items are decoded below.
        let mut batch = Vec::new();
        match self.replay.ensure(A::SIZE).await {
            Ok(true) => {}
            Ok(false) => {
                batch.push(Err(Error::Corruption(format!(
                    "blob ended before position {}",
                    self.pos
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

        // Decode only whole items that are already buffered, capped by the replay byte budget
        // and the journal's logical end.
        let available = (self.replay.remaining() / A::SIZE) as u64;
        let remaining = self.end_pos - self.pos;
        let count = available.min(self.items_per_batch as u64).min(remaining) as usize;
        let Some(next_pos) = self.pos.checked_add(count as u64) else {
            batch.push(Err(Error::OffsetOverflow));
            self.pos = self.end_pos;
            return Some((batch, self));
        };
        batch.reserve(count);

        let base = self.pos;
        for i in 0..count {
            match A::read(&mut self.replay) {
                Ok(item) => batch.push(Ok((base + i as u64, item))),
                Err(err) => {
                    batch.push(Err(Error::Codec(err)));
                    self.pos = self.end_pos;
                    return Some((batch, self));
                }
            }
        }
        self.pos = next_pos;
        Some((batch, self))
    }
}

/// Configuration for `Journal` storage.
#[derive(Clone)]
pub struct Config {
    /// The partition holding the journal's blob. The journal owns the partition.
    pub partition: String,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for the blob.
    pub write_buffer: NonZeroUsize,
}

/// Implementation of [super::Mutable] for fixed-size value journals.
///
/// # Recovery
///
/// The storage backend guarantees atomic sync, so torn or trailing partial writes cannot
/// survive a crash. Recovery derives the bounds from the blob's byte length and pruned floor
/// and returns [Error::Corruption] on a partial item instead of repairing.
pub struct Journal<E: Context, A> {
    /// The storage context.
    context: E,

    /// The partition holding [Self::blob].
    partition: String,

    /// The page cache backing [Self::blob] (retained to rebuild it after a clear, an ALPHA
    /// path — hence the manual stability gate).
    ///
    /// Pruned pages may linger in the shared cache after a prune: the journal never reads
    /// below its own boundary, so lingering entries are a memory-hygiene note, not a
    /// correctness concern (they age out through the cache's normal replacement).
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    page_cache: CacheRef,

    /// The write buffer size for [Self::blob] (retained to rebuild it after a clear, an
    /// ALPHA path — hence the manual stability gate).
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    write_buffer: NonZeroUsize,

    /// A raw handle to the journal's blob, used for the clear paths' (ALPHA — hence the
    /// manual stability gate) direct resize and prune (the writer's resize would materialize
    /// zeros and fsync mid-transition). Only used while [Self::blob] is quiescent and about
    /// to be rebuilt.
    #[cfg(not(any(
        commonware_stability_BETA,
        commonware_stability_GAMMA,
        commonware_stability_DELTA,
        commonware_stability_EPSILON,
        commonware_stability_RESERVED
    )))]
    raw: E::Blob,

    /// The single blob holding every item.
    blob: Writer<E::Blob>,

    /// The readable positions; `bounds.end` is the next append position.
    bounds: Range<u64>,

    /// Whether the blob has mutations not yet staged for durability.
    dirty: bool,

    /// Shared with [Reader]s.
    metrics: Arc<Metrics<E>>,

    _phantom: PhantomData<A>,
}

impl<E: Context, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry in bytes. Evaluating this rejects zero-size item types at compile
    /// time, which would otherwise divide by zero in the chunk math.
    pub const CHUNK_SIZE: NonZeroUsize = match NonZeroUsize::new(A::SIZE) {
        Some(size) => size,
        None => panic!("journal item size must be nonzero"),
    };

    /// Size of each entry in bytes (as u64).
    pub const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE.get() as u64;

    /// Convert an item count to a byte length, failing on overflow.
    fn items_to_bytes(items: u64) -> Result<u64, Error> {
        items
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)
    }

    /// Convert the blob's pruned floor to the pruning boundary. The journal only ever prunes
    /// at item multiples and `from_blob` rejects a misaligned stored floor as corruption, so
    /// every caller passes an item-aligned floor.
    fn floor_to_boundary(floor: u64) -> u64 {
        debug_assert!(
            floor.is_multiple_of(Self::CHUNK_SIZE_U64),
            "pruned floor is not item-aligned"
        );
        floor / Self::CHUNK_SIZE_U64
    }

    /// Initialize a new `Journal` instance.
    ///
    /// The backing blob is opened but not read during initialization. The `replay` method can
    /// be used to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        // The base context is consumed by the metric registrations below; storage operations
        // run on a dedicated child bound once here.
        let ops_context = context.child("blob");
        let (raw, size) = ops_context
            .open(&cfg.partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;
        Self::from_blob(context, ops_context, cfg, raw, size).await
    }

    /// Assemble a journal over `raw`, deriving the bounds from its size and pruned floor.
    async fn from_blob(
        context: E,
        ops_context: E,
        cfg: Config,
        raw: E::Blob,
        size: u64,
    ) -> Result<Self, Error> {
        if !size.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::Corruption(format!(
                "blob has a partial item: {size} bytes"
            )));
        }
        let floor = raw.floor();
        if !floor.is_multiple_of(Self::CHUNK_SIZE_U64) {
            return Err(Error::Corruption(format!(
                "pruned floor splits an item: {floor} bytes (foreign write or item size change)"
            )));
        }
        let bounds = Self::floor_to_boundary(floor)..size / Self::CHUNK_SIZE_U64;

        let blob = Writer::new(
            raw.clone(),
            size,
            cfg.write_buffer.get(),
            cfg.page_cache.clone(),
        )
        .await
        .map_err(Error::Runtime)?;

        let metrics = Metrics::new(context);
        metrics.update(bounds.end, bounds.start);

        Ok(Self {
            context: ops_context,
            partition: cfg.partition,
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
            #[cfg(not(any(
                commonware_stability_BETA,
                commonware_stability_GAMMA,
                commonware_stability_DELTA,
                commonware_stability_EPSILON,
                commonware_stability_RESERVED
            )))]
            raw,
            blob,
            bounds,
            dirty: false,
            metrics: Arc::new(metrics),
            _phantom: PhantomData,
        })
    }

    /// Materialize the fully pruned image on `raw`: `bytes` of unreadable prefix,
    /// hole-extended (or shrunk) then pruned — both cheap metadata mutations whose durability
    /// follows the blob's next sync.
    ///
    /// # Panics
    ///
    /// Panics if `bytes` is below the blob's floor (the caller routes that case through
    /// removal).
    #[commonware_macros::stability(ALPHA)]
    async fn materialize(raw: &E::Blob, bytes: u64) -> Result<(), Error> {
        assert!(bytes >= raw.floor(), "cannot materialize below the floor");
        raw.resize(bytes).await.map_err(Error::Runtime)?;
        raw.prune(bytes).await.map_err(Error::Runtime)?;
        Ok(())
    }

    /// Initialize a `Journal` in a fully-pruned state at `size`: existing data is cleared and the
    /// journal behaves as if `size` items were appended then pruned. It is empty (`bounds` is
    /// `size..size`) and the next `append` writes at position `size`. Used for state sync.
    ///
    /// # Crash Safety
    ///
    /// The cleared image is durable when this call returns. A crash during the call recovers
    /// the journal in its prior state or with bounds `size..size` — except when `size`
    /// precedes the prior pruning boundary, which forces a blob recreation whose intermediate
    /// crash state is an empty journal at position 0 (see the module docs on clearing).
    #[commonware_macros::stability(ALPHA)]
    pub async fn init_at_size(context: E, cfg: Config, size: u64) -> Result<Self, Error> {
        // A journal sized at `u64::MAX` can never accept an append (the successor size
        // overflows), so reject it before mutating anything. The size must also be
        // byte-representable, since the blob materializes at `size * CHUNK_SIZE` bytes.
        if size == u64::MAX {
            return Err(Error::SizeOverflow);
        }
        let bytes = Self::items_to_bytes(size)?;

        let ops_context = context.child("blob");
        let (raw, _) = ops_context
            .open(&cfg.partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;

        // Rebuild the pruned image in place when the target is at or above the floor;
        // otherwise remove and recreate the blob (nothing may shrink below the floor).
        let raw = if bytes >= raw.floor() {
            Self::materialize(&raw, bytes).await?;
            raw
        } else {
            Self::recreate_pruned(&ops_context, &cfg.partition, raw, bytes).await?
        };

        // Commit the cleared image so it survives a crash after this call returns.
        let mut batch = ops_context.batch().await.map_err(Error::Runtime)?;
        batch.sync(&raw);
        batch.apply_sync().await.map_err(Error::Runtime)?;

        Self::from_blob(context, ops_context, cfg, raw, bytes).await
    }

    /// Remove the journal's blob (a committed step) and recreate it as `bytes` of fully
    /// pruned prefix (uncommitted: the caller makes it durable). Used when a clear targets a
    /// position below the pruning boundary; a crash between the two steps recovers an empty
    /// journal at position 0.
    #[commonware_macros::stability(ALPHA)]
    async fn recreate_pruned(
        context: &E,
        partition: &str,
        old: E::Blob,
        bytes: u64,
    ) -> Result<E::Blob, Error> {
        drop(old);
        let mut batch = context.batch().await.map_err(Error::Runtime)?;
        batch.remove(partition, None);
        batch.apply_sync().await.map_err(Error::Runtime)?;

        let (raw, size) = context
            .open(partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;
        assert_eq!(size, 0, "the applied removal emptied the partition");
        Self::materialize(&raw, bytes).await?;
        Ok(raw)
    }

    /// The storage context the journal operates on.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) const fn context(&self) -> &E {
        &self.context
    }

    /// Stage the blob's durability with `batch`: item data and the pruned floor land in ONE
    /// commit.
    ///
    /// Dirty tracking resets immediately: the caller must apply the batch (storage failures
    /// are fatal, so an abandoned batch has no recovery path anyway).
    pub(crate) async fn sync_into(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        if self.dirty {
            self.blob.sync_into(batch).await.map_err(Error::Runtime)?;
            self.dirty = false;
        }
        Ok(())
    }

    /// Durably persist the current state of the structure with a single sync.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.sync_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// A reader borrowing the journal's live state.
    pub(super) fn reader(&self) -> Reader<'_, E, A> {
        Reader {
            blob: &self.blob,
            bounds: self.bounds.clone(),
            metrics: self.metrics.clone(),
            _phantom: PhantomData,
        }
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub const fn size(&self) -> u64 {
        self.bounds.end
    }

    /// Append a new item to the journal, returning its position.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn append(&mut self, item: &A) -> Result<u64, Error> {
        let _timer = self.metrics.append_timer();
        self.metrics.append_calls.inc();
        self.append_many_inner(Many::Flat(std::slice::from_ref(item)))
            .await
    }

    /// Append items to the journal, returning the position of the last item appended.
    ///
    /// Returns [Error::EmptyAppend] if items is empty.
    pub async fn append_many<'a>(&'a mut self, items: Many<'a, A>) -> Result<u64, Error> {
        let _timer = self.metrics.append_many_timer();
        self.metrics.append_many_calls.inc();
        self.append_many_inner(items).await
    }

    // Shared implementation for `append` and `append_many`; public wrappers record metrics.
    async fn append_many_inner<'a>(&'a mut self, items: Many<'a, A>) -> Result<u64, Error> {
        let prepared = self.prepare_append(items);
        self.write_encoded(prepared).await
    }

    /// Encode `items` into a buffer that can be appended later with [`Self::append_prepared`].
    ///
    /// This lets callers serialize borrowed items synchronously, release those borrows, and
    /// perform the append without holding unrelated locks across journal I/O.
    pub fn prepare_append(&self, items: Many<'_, A>) -> PreparedAppend<A> {
        // Encode all items into a single contiguous buffer up front.
        // Uses Write::write directly to avoid per-item Bytes allocations from Encode::encode.
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
    pub async fn append_prepared(&mut self, prepared: PreparedAppend<A>) -> Result<u64, Error> {
        let _timer = self.metrics.append_prepared_timer();
        self.metrics.append_prepared_calls.inc();
        self.write_encoded(prepared).await
    }

    // Write pre-encoded items; shared by all append paths. Records no call metrics.
    async fn write_encoded(&mut self, prepared: PreparedAppend<A>) -> Result<u64, Error> {
        let items_buf = prepared.buf;
        let items_count = (items_buf.len() / A::SIZE) as u64;
        if items_count == 0 {
            return Err(Error::EmptyAppend);
        }

        // Reject the append before writing anything if it would push the size past `u64::MAX`
        // items or past a byte-representable blob size.
        let end = self
            .bounds
            .end
            .checked_add(items_count)
            .ok_or(Error::SizeOverflow)?;
        Self::items_to_bytes(end)?;

        self.blob
            .append_owned(IoBuf::from(items_buf))
            .await
            .map_err(Error::Runtime)?;
        self.bounds.end = end;
        self.dirty = true;

        self.metrics.update(self.bounds.end, self.bounds.start);
        Ok(self.bounds.end - 1)
    }

    /// Rewind the journal to the given `size`. Returns [Error::InvalidRewind] if `size` is beyond
    /// the current size, or [Error::ItemPruned] if it precedes the pruning boundary. The journal
    /// is not synced after rewinding.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until `sync()` is
    ///   called.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.bounds.end) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        if size < self.bounds.start {
            return Err(Error::ItemPruned(size));
        }

        self.blob
            .resize(Self::items_to_bytes(size)?)
            .await
            .map_err(Error::Runtime)?;
        self.bounds.end = size;
        self.dirty = true;
        self.metrics.update(self.bounds.end, self.bounds.start);

        Ok(())
    }

    /// [Self::rewind], staged with `batch`: the truncation publishes and becomes durable when
    /// the caller applies the batch, atomically with everything else it stages. Even when no
    /// bytes drop, the blob's flushed state joins the batch for durability membership, so no
    /// dirty state survives the commit.
    ///
    /// Once staged the batch is this blob's ONE writer: the caller must apply the batch
    /// before mutating the journal again.
    pub(crate) async fn rewind_into(
        &mut self,
        size: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        if size > self.bounds.end {
            return Err(Error::InvalidRewind(size));
        }
        if size < self.bounds.start {
            return Err(Error::ItemPruned(size));
        }

        self.blob
            .resize_into(Self::items_to_bytes(size)?, batch)
            .await
            .map_err(Error::Runtime)?;
        self.bounds.end = size;
        self.dirty = false;
        self.metrics.update(self.bounds.end, self.bounds.start);

        Ok(())
    }

    /// Return the location before which all items have been pruned.
    pub const fn pruning_boundary(&self) -> u64 {
        self.bounds.start
    }

    /// Prune items at positions below `min_item_pos` (capped to the journal's size), exactly:
    /// the new pruning boundary IS the requested position. Returns true if the boundary
    /// advanced. Positions at or above the new boundary stay readable.
    ///
    /// The blob's dirty bytes and its new floor land in ONE commit. The floor itself is a
    /// mutation whose durability follows that commit: a crash beforehand regresses it (never
    /// the reverse) and consumers re-prune.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<bool, Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        if !self.prune_into(min_item_pos, &mut batch).await? {
            return Ok(false);
        }
        batch.apply_sync().await.map_err(Error::Runtime)?;
        Ok(true)
    }

    /// Stage a prune with `batch`: the caller applies the batch. Returns true if the boundary
    /// advanced.
    ///
    /// The blob's buffered bytes are flushed and the native prune runs immediately (the prune
    /// target may be justified by an appended-but-unflushed item, e.g. a consumer's commit
    /// record); the batch then stages the blob's durability so floor and data commit
    /// together.
    ///
    /// # Caller contract
    ///
    /// `batch` must not already stage over this journal's blob: the native prune requires the
    /// blob to have no open batch (writer exclusivity), so this must be the batch's first
    /// touch of the journal. Call it before [Self::sync_into] when both join one batch.
    pub(crate) async fn prune_into(
        &mut self,
        min_item_pos: u64,
        batch: &mut E::Batch,
    ) -> Result<bool, Error> {
        // Cap to the journal's size (which the flush below makes fully physical).
        let min = min_item_pos.min(self.bounds.end);
        let offset = Self::items_to_bytes(min)?;
        if offset <= self.blob.floor() {
            return Ok(false);
        }

        self.blob.prune(offset).await.map_err(Error::Runtime)?;
        self.bounds.start = Self::floor_to_boundary(self.blob.floor());
        debug_assert_eq!(self.bounds.start, min, "native pruning is byte-exact");

        self.blob.sync_into(batch).await.map_err(Error::Runtime)?;
        self.dirty = false;

        self.metrics.update(self.bounds.end, self.bounds.start);

        Ok(true)
    }

    /// Remove any persisted data created by the journal: the data partition's removal lands
    /// in ONE atomic commit, so destruction is all-or-nothing.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch);
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: the partition removal lands when the caller
    /// applies the batch with `apply_sync`, atomically with everything else it stages.
    pub(crate) fn destroy_into(self, batch: &mut E::Batch) {
        drop(self.blob);
        batch.remove(&self.partition, None);
    }

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused. After clearing, the
    /// journal will behave as if initialized with `init_at_size(new_size)`.
    ///
    /// # Crash Safety
    ///
    /// The cleared image is durable when this call returns; crash states match
    /// [Self::init_at_size].
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn clear_to_size(&mut self, new_size: u64) -> Result<(), Error> {
        // A journal sized at `u64::MAX` can never accept an append, matching `init_at_size`,
        // and the target must be byte-representable.
        if new_size == u64::MAX {
            return Err(Error::SizeOverflow);
        }
        let bytes = Self::items_to_bytes(new_size)?;

        if bytes >= self.blob.floor() {
            let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
            self.stage_clear(new_size, &mut batch).await?;
            batch.apply_sync().await.map_err(Error::Runtime)?;
            return self.finish_clear(new_size).await;
        }

        // Clearing below the pruning boundary cannot reuse the blob (nothing may shrink below
        // the floor): remove the partition (one commit), then recreate the pruned image and
        // commit it. A crash between the two commits recovers an empty journal at position 0.
        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.stage_remove(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)?;

        let mut batch = self.context.batch().await.map_err(Error::Runtime)?;
        self.finish_recreate(new_size, &mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// Stage the removal of the journal's whole partition with `batch` (an ALPHA clear-path
    /// step). Once the caller applies the batch, the journal holds handles to a removed blob
    /// and must not be touched until [Self::finish_recreate] rebuilds it.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn stage_remove(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        // Settle any started sync before the blob is removed out from under the writer.
        self.blob.wait_for_sync().await.map_err(Error::Runtime)?;
        batch.remove(&self.partition, None);
        Ok(())
    }

    /// Rebuild the journal after an applied [Self::stage_remove]: recreate the blob as
    /// `new_size * CHUNK_SIZE` bytes of fully pruned prefix and stage the new image's
    /// durability with `batch` (the caller applies it). The journal is empty at `new_size`
    /// once the batch lands.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn finish_recreate(
        &mut self,
        new_size: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        let bytes = Self::items_to_bytes(new_size)?;
        let (raw, size) = self
            .context
            .open(&self.partition, BLOB_NAME)
            .await
            .map_err(Error::Runtime)?;
        assert_eq!(size, 0, "the applied removal emptied the partition");
        Self::materialize(&raw, bytes).await?;
        batch.sync(&raw);
        self.raw = raw;
        self.bounds = new_size..new_size;
        self.finish_clear(new_size).await
    }

    /// Stage this journal's clear with `batch`: the blob is transformed IN PLACE into
    /// `new_size * CHUNK_SIZE` bytes of fully pruned prefix (immediate, unsynced mutations)
    /// and its durability joins the batch, so the cleared image commits atomically with
    /// everything else the caller stages. The caller applies the batch, then rebuilds the
    /// write path with [Self::finish_clear]; the journal must not be touched in between.
    ///
    /// # Panics
    ///
    /// Panics if `new_size` precedes the pruning boundary: the in-place transform cannot
    /// shrink below the floor. Callers clear at or above the current size.
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn stage_clear(
        &mut self,
        new_size: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        // Settle any started sync before mutating the blob out from under the writer.
        self.blob.wait_for_sync().await.map_err(Error::Runtime)?;
        Self::materialize(&self.raw, Self::items_to_bytes(new_size)?).await?;
        batch.sync(&self.raw);
        self.bounds = new_size..new_size;
        Ok(())
    }

    /// Rebuild the write path over the cleared blob and reset RAM state (the staged clear
    /// must have been applied).
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn finish_clear(&mut self, new_size: u64) -> Result<(), Error> {
        assert!(
            self.bounds == (new_size..new_size),
            "finish_clear must follow a clear to the same size"
        );
        self.blob = Writer::new(
            self.raw.clone(),
            Self::items_to_bytes(new_size)?,
            self.write_buffer.get(),
            self.page_cache.clone(),
        )
        .await
        .map_err(Error::Runtime)?;
        self.dirty = false;
        self.metrics.update(self.bounds.end, self.bounds.start);
        Ok(())
    }
}

/// A reader borrowing a fixed journal's live state.
pub(super) struct Reader<'a, E: Context, A> {
    blob: &'a Writer<E::Blob>,
    bounds: Range<u64>,
    metrics: Arc<Metrics<E>>,
    _phantom: PhantomData<A>,
}

impl<E: Context, A: CodecFixedShared> Reader<'_, E, A> {
    /// Validate a position to be read: must lie within `bounds`.
    const fn validate_readable(&self, pos: u64) -> Result<(), Error> {
        if pos >= self.bounds.end {
            return Err(Error::ItemOutOfRange(pos));
        }
        if pos < self.bounds.start {
            return Err(Error::ItemPruned(pos));
        }
        Ok(())
    }

    /// Resolve a position to its byte offset within the blob.
    fn locate(&self, pos: u64) -> Result<u64, Error> {
        self.validate_readable(pos)?;
        pos.checked_mul(Journal::<E, A>::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)
    }

    /// Shared body of [`super::Contiguous::read_many`]; the callers record the batch-read
    /// metrics, so routing them through `read_many` would count every batch twice.
    pub(super) async fn read_many_inner(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let offsets = positions
            .iter()
            .map(|&pos| self.locate(pos))
            .collect::<Result<Vec<u64>, _>>()?;

        // One batched read serves page-cache and tip-buffer hits under a single lock
        // acquisition and reads only true misses from the blob (concurrently).
        let mut buf = vec![0u8; positions.len() * A::SIZE];
        let hits = self
            .blob
            .read_many_into(&mut buf, &offsets, Journal::<E, A>::CHUNK_SIZE)
            .await
            .map_err(Error::Runtime)? as u64;

        let mut result: Vec<A> = Vec::with_capacity(positions.len());
        for slice in buf.chunks_exact(A::SIZE) {
            result.push(A::decode(slice).map_err(Error::Codec)?);
        }

        self.metrics.cache_hits.inc_by(hits);
        self.metrics
            .cache_misses
            .inc_by(positions.len() as u64 - hits);
        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result)
    }

    /// Probe `positions` (strictly increasing) against the page cache, returning one slot per
    /// position: `Some(item)` for sync hits and `None` for positions that require I/O, fail to
    /// decode, or fall outside `bounds()`.
    pub(super) fn probe_items(&self, positions: &[u64]) -> Vec<Option<A>> {
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        let mut out: Vec<Option<A>> = (0..positions.len()).map(|_| None).collect();

        // Sorted positions put pruned ones in a prefix and out-of-range ones in a suffix, so
        // validation trims the batch instead of poisoning the whole probe.
        let start = positions.partition_point(|&pos| pos < self.bounds.start);
        let end = positions.partition_point(|&pos| pos < self.bounds.end);
        let valid = &positions[start..end];
        if valid.is_empty() {
            return out;
        }
        let Ok(offsets) = valid
            .iter()
            .map(|&pos| {
                pos.checked_mul(Journal::<E, A>::CHUNK_SIZE_U64)
                    .ok_or(Error::OffsetOverflow)
            })
            .collect::<Result<Vec<u64>, _>>()
        else {
            return out;
        };

        // Serve the probe from the per-thread scratch buffer. Stale bytes from a previous probe
        // are harmless: slots the cache cannot serve are reported as misses and never decoded.
        let mut scratch =
            Cached::take(&PROBE_SCRATCH, || Ok::<_, ()>(Vec::new()), |_| Ok(())).unwrap();
        let need = valid.len() * A::SIZE;
        if scratch.len() < need {
            scratch.resize(need, 0);
        }
        let buf = &mut scratch[..need];
        let misses = self
            .blob
            .try_read_many_sync_into(buf, &offsets, Journal::<E, A>::CHUNK_SIZE);
        let mut hits = 0u64;
        let mut misses = misses.into_iter().peekable();
        for (idx, slice) in buf.chunks_exact(A::SIZE).enumerate() {
            if misses.peek() == Some(&idx) {
                misses.next();
                continue;
            }
            // A decode failure declines to a miss: the async completion re-reads the
            // item and bubbles the failure as [Error::Codec], like every async read path.
            if let Ok(item) = A::decode(slice) {
                out[start + idx] = Some(item);
                hits += 1;
            }
        }
        self.metrics.cache_hits.inc_by(hits);
        self.metrics.items_read.inc_by(hits);
        out
    }
}

impl<E: Context, A: CodecFixedShared> super::Contiguous for Reader<'_, E, A> {
    type Item = A;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, pos: u64) -> Result<A, Error> {
        self.metrics.read_calls.inc();

        // Serve from the page cache synchronously when possible, avoiding the async storage path.
        if let Some(item) = self.try_read_sync(pos) {
            return Ok(item);
        }

        let _timer = self.metrics.read_timer();
        let offset = self.locate(pos)?;
        self.metrics.cache_misses.inc();
        let bufs = self
            .blob
            .read_at(offset, A::SIZE)
            .await
            .map_err(Error::Runtime)?;
        let item = A::decode(bufs.coalesce()).map_err(Error::Codec)?;
        self.metrics.items_read.inc();
        Ok(item)
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        let _timer = self.metrics.read_many_timer();
        self.metrics.read_many_calls.inc();
        self.read_many_inner(positions).await
    }

    fn try_read_sync(&self, pos: u64) -> Option<A> {
        let mut buf = vec![0u8; A::SIZE];
        let item = match self.locate(pos) {
            Ok(offset) if self.blob.try_read_sync_into(&mut buf, offset) => {
                A::decode(&buf[..]).ok()
            }
            _ => None,
        };
        if item.is_some() {
            self.metrics.cache_hits.inc();
            self.metrics.items_read.inc();
        }
        item
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<A>> {
        self.probe_items(positions)
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error> {
        replay_stream(self.blob, self.bounds.clone(), start_pos, buffer)
    }
}

impl<E: Context, A: CodecFixedShared> super::Contiguous for Journal<E, A> {
    type Item = A;

    fn bounds(&self) -> Range<u64> {
        self.bounds.clone()
    }

    async fn read(&self, pos: u64) -> Result<A, Error> {
        self.reader().read(pos).await
    }

    async fn read_many(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        self.reader().read_many(positions).await
    }

    fn try_read_sync(&self, pos: u64) -> Option<A> {
        self.reader().try_read_sync(pos)
    }

    fn try_read_many_sync(&self, positions: &[u64]) -> Vec<Option<A>> {
        self.reader().probe_items(positions)
    }

    async fn replay(
        &self,
        start_pos: u64,
        buffer: NonZeroUsize,
    ) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send, Error> {
        replay_stream(&self.blob, self.bounds.clone(), start_pos, buffer)
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

    async fn sync(&mut self) -> Result<(), Error> {
        Self::sync(self).await
    }

    async fn destroy(self) -> Result<(), Error> {
        Self::destroy(self).await
    }
}

#[commonware_macros::stability(ALPHA)]
impl<E: Context, A: CodecFixedShared> authenticated::Inner<E> for Journal<E, A> {
    type Config = Config;

    async fn init<
        F: merkle::Family,
        H: commonware_cryptography::Hasher,
        S: commonware_parallel::Strategy,
    >(
        context: E,
        merkle_cfg: merkle::full::Config<S>,
        journal_cfg: Self::Config,
        rewind_predicate: fn(&A) -> bool,
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
    use crate::journal::contiguous::{tests::run_contiguous_tests, Contiguous as _};
    use commonware_codec::FixedSize as _;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        deterministic, Batchable as _, BufferPooler, Metrics as _, Runner, Storage, Supervisor as _,
    };
    use commonware_utils::{NZUsize, NZU16};
    use futures::{pin_mut, FutureExt as _, StreamExt};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(44);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(3);
    const CHUNK: u64 = Digest::SIZE as u64;

    /// Generate a SHA-256 digest for the given value.
    fn test_digest(value: u64) -> Digest {
        Sha256::hash(&value.to_be_bytes())
    }

    fn test_cfg(pooler: &impl BufferPooler) -> Config {
        Config {
            partition: "test-partition".into(),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(2048),
        }
    }

    /// Extract a metric counter's value from encoded metrics output.
    fn counter(buffer: &str, name: &str) -> u64 {
        buffer
            .lines()
            .find(|l| l.contains(name) && !l.starts_with('#'))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .expect("counter missing")
    }

    /// The generic suite over the fixed journal.
    #[test_traced]
    fn test_fixed_journal_contiguous_suite() {
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
                        partition: format!("suite-{test_name}"),
                        page_cache: CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE),
                        write_buffer: NZUsize!(2048),
                    };
                    Journal::<_, u64>::init(context, cfg).await
                }
                .boxed()
            })
            .await;
        });
    }

    #[test_traced]
    fn test_fixed_journal_append_and_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
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

            let mut journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 1);

            // Append two more items
            pos = journal.append(&test_digest(1)).await.unwrap();
            assert_eq!(pos, 1);
            pos = journal.append(&test_digest(2)).await.unwrap();
            assert_eq!(pos, 2);

            // Read the items back
            for i in 0..3u64 {
                let item = journal.read(i).await.expect("failed to read data");
                assert_eq!(item, test_digest(i));
            }
            let err = journal.read(3).await.expect_err("expected read to fail");
            assert!(matches!(err, Error::ItemOutOfRange(3)));

            journal.sync().await.expect("failed to sync journal");

            // Pruning is exact: the boundary lands at the requested position.
            assert!(journal.prune(2).await.unwrap());
            assert_eq!(journal.bounds(), 2..3);

            // Reading pruned positions fails; the retained item stays readable.
            assert!(matches!(journal.read(0).await, Err(Error::ItemPruned(0))));
            assert!(matches!(journal.read(1).await, Err(Error::ItemPruned(1))));
            assert_eq!(journal.read(2).await.unwrap(), test_digest(2));

            // Should be able to continue to append items
            for i in 3..10 {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, i);
            }

            // A no-op prune returns false and moves nothing.
            assert!(!journal.prune(0).await.unwrap());
            assert!(!journal.prune(2).await.unwrap());
            assert_eq!(journal.bounds(), 2..10);

            // Prune (more than) everything in the journal: capped at the size.
            assert!(journal.prune(10000).await.unwrap());
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 10);

            // Replaying from 0 should fail since all items are pruned.
            {
                let result = journal.replay(0, NZUsize!(1024)).await;
                assert!(matches!(result, Err(Error::ItemPruned(0))));
            }

            // Replaying from the pruning boundary should return an empty stream.
            {
                let stream = journal
                    .replay(journal.bounds().start, NZUsize!(1024))
                    .await
                    .expect("failed to replay journal from pruning boundary");
                pin_mut!(stream);
                assert!(stream.next().await.is_none());
            }

            journal.destroy().await.unwrap();
        });
    }

    /// The directed boundary test: prune mid-journal, the boundary is exact and persists
    /// across a restart once synced; an unsynced prune regresses across a crash and can be
    /// re-applied.
    #[test_traced]
    fn test_fixed_journal_prune_boundary_persistence_and_regression() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..200u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // A committed prune to an arbitrary position: the boundary is exact.
            assert!(journal.prune(37).await.unwrap());
            assert_eq!(journal.bounds(), 37..200);

            // Stage a further prune whose commit never lands: the floor advances in RAM but
            // the crash below discards it.
            let mut batch = journal.context().batch().await.unwrap();
            assert!(journal.prune_into(150, &mut batch).await.unwrap());
            assert_eq!(journal.bounds(), 150..200);
            drop(batch);
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // The unsynced prune regressed to the last committed boundary.
            assert_eq!(journal.bounds(), 37..200);
            assert_eq!(journal.read(37).await.unwrap(), test_digest(37));

            // Re-pruning after the regression works and is exact.
            assert!(journal.prune(150).await.unwrap());
            assert_eq!(journal.bounds(), 150..200);
            assert!(matches!(
                journal.read(149).await,
                Err(Error::ItemPruned(149))
            ));
            assert_eq!(journal.read(150).await.unwrap(), test_digest(150));

            journal.destroy().await.unwrap();
        });
    }

    /// Append a lot of data to make sure we exercise page cache paging boundaries.
    #[test_traced]
    fn test_fixed_journal_append_a_lot_of_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for i in 0u64..19_999 {
                journal.append(&test_digest(i)).await.unwrap();
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
        const ITEMS: u64 = 703;
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0u64..ITEMS {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, i);
            }

            // Read them back the usual way.
            for i in 0u64..ITEMS {
                let item: Digest = journal.read(i).await.unwrap();
                assert_eq!(item, test_digest(i), "i={i}");
            }

            // Replay should return all items.
            {
                let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
                let mut items = Vec::new();
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(test_digest(pos), item, "pos={pos}");
                    items.push(pos);
                }
                assert_eq!(items.len(), ITEMS as usize);
                for (i, pos) in items.iter().enumerate() {
                    assert_eq!(i as u64, *pos);
                }
            }

            // A partial replay starts mid-journal (mid-page and mid-chunk).
            {
                const START_POS: u64 = 53;
                let stream = journal.replay(START_POS, NZUsize!(1024)).await.unwrap();
                let mut count = 0;
                pin_mut!(stream);
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert!(pos >= START_POS);
                    assert_eq!(test_digest(pos), item);
                    count += 1;
                }
                assert_eq!(count, ITEMS - START_POS);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_replay_stops_after_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0u64..30 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen with a fresh page cache so replay must hit storage, then inject read
            // faults: the stream must surface the error once and terminate.
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                read_rate: Some(1.0),
                ..Default::default()
            };
            {
                let stream = journal.replay(0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);

                assert!(matches!(
                    stream.next().await.unwrap(),
                    Err(Error::Runtime(_))
                ));
                assert!(stream.next().await.is_none());
            }

            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            journal.destroy().await.unwrap();
        });
    }

    /// A blob whose byte length is not a whole number of items is corruption.
    #[test_traced]
    fn test_fixed_journal_partial_item_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            {
                let mut journal = Journal::init(context.child("first"), cfg.clone())
                    .await
                    .unwrap();
                journal.append(&test_digest(0)).await.unwrap();
                journal.sync().await.unwrap();
            }

            // Extend the blob by a partial item (external corruption).
            let (blob, size) = context
                .open(&cfg.partition, super::BLOB_NAME)
                .await
                .unwrap();
            blob.write_at_sync(size, vec![0u8; 3]).await.unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewinding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0u64..25 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            // Rewind forward is invalid, rewind to the current size is a no-op.
            assert!(matches!(
                journal.rewind(26).await,
                Err(Error::InvalidRewind(26))
            ));
            journal.rewind(25).await.unwrap();
            assert_eq!(journal.size(), 25);

            // Rewind mid-journal, then append: positions continue from the rewind point.
            journal.rewind(20).await.unwrap();
            assert_eq!(journal.size(), 20);
            assert!(matches!(
                journal.read(20).await,
                Err(Error::ItemOutOfRange(20))
            ));
            let pos = journal.append(&test_digest(100)).await.unwrap();
            assert_eq!(pos, 20);
            assert_eq!(journal.read(20).await.unwrap(), test_digest(100));

            // Rewind survives sync + reopen.
            journal.rewind(5).await.unwrap();
            journal.sync().await.unwrap();
            drop(journal);
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 5);
            for i in 0u64..5 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            // Rewinding below the pruning boundary fails.
            journal.prune(3).await.unwrap();
            assert!(matches!(journal.rewind(2).await, Err(Error::ItemPruned(2))));

            // Rewinding TO the boundary empties the journal.
            journal.rewind(3).await.unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 3);

            journal.destroy().await.unwrap();
        });
    }

    /// An unsynced rewind is rolled back by a crash.
    #[test_traced]
    fn test_fixed_journal_rewind_crash_before_sync() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.rewind(4).await.unwrap();
            assert_eq!(journal.size(), 4);
            // No sync: the crash below discards the rewind.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 10);
            for i in 0u64..10 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);

            // Init at an arbitrary position: empty, and the next append lands there.
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 37)
                    .await
                    .unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 37);
            assert!(matches!(journal.read(36).await, Err(Error::ItemPruned(36))));

            let pos = journal.append(&test_digest(37)).await.unwrap();
            assert_eq!(pos, 37);
            assert_eq!(journal.read(37).await.unwrap(), test_digest(37));
            journal.sync().await.unwrap();
            drop(journal);

            // The cleared image persists across a plain reopen with no auxiliary record.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 37..38);
            assert_eq!(journal.read(37).await.unwrap(), test_digest(37));
            drop(journal);

            // Re-initializing at a LOWER size than the boundary recreates the blob.
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("third"), cfg.clone(), 7)
                    .await
                    .unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 7);
            let pos = journal.append(&test_digest(7)).await.unwrap();
            assert_eq!(pos, 7);
            journal.destroy().await.unwrap();

            // Init at size zero behaves like a fresh journal.
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("fourth"), cfg.clone(), 0)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            let pos = journal.append(&test_digest(0)).await.unwrap();
            assert_eq!(pos, 0);
            journal.destroy().await.unwrap();

            // A journal sized at u64::MAX (or beyond byte representability) is rejected.
            assert!(matches!(
                Journal::<_, Digest>::init_at_size(context.child("fifth"), cfg.clone(), u64::MAX)
                    .await,
                Err(Error::SizeOverflow)
            ));
            assert!(matches!(
                Journal::<_, Digest>::init_at_size(
                    context.child("sixth"),
                    cfg.clone(),
                    u64::MAX / CHUNK + 1
                )
                .await,
                Err(Error::OffsetOverflow)
            ));
        });
    }

    /// The cleared image is durable when `init_at_size` returns: a crash immediately after
    /// recovers the cleared journal.
    #[test_traced]
    fn test_fixed_journal_init_at_size_durable_without_sync() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 53)
                    .await
                    .unwrap();
            assert_eq!(journal.bounds(), 53..53);
            // No sync: init_at_size itself must have committed the image.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 53..53);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_prune_and_append() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 100)
                    .await
                    .unwrap();

            for i in 100u64..120 {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, i);
            }

            // Prune within the appended range: exact boundary.
            assert!(journal.prune(110).await.unwrap());
            assert_eq!(journal.bounds(), 110..120);
            assert!(matches!(
                journal.read(109).await,
                Err(Error::ItemPruned(109))
            ));
            assert_eq!(journal.read(110).await.unwrap(), test_digest(110));

            // Replay from the boundary.
            {
                let stream = journal.replay(110, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let mut count = 0;
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(test_digest(pos), item);
                    count += 1;
                }
                assert_eq!(count, 10);
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Clear forward (above the current size): in-place.
            journal.clear_to_size(50).await.unwrap();
            assert_eq!(journal.bounds(), 50..50);
            assert!(matches!(journal.read(5).await, Err(Error::ItemPruned(5))));
            let pos = journal.append(&test_digest(50)).await.unwrap();
            assert_eq!(pos, 50);
            journal.sync().await.unwrap();

            // Clear backward but at/above the boundary: in-place shrink.
            journal.clear_to_size(50).await.unwrap();
            assert_eq!(journal.bounds(), 50..50);

            // Clear backward BELOW the boundary: blob recreation.
            journal.clear_to_size(3).await.unwrap();
            assert_eq!(journal.bounds(), 3..3);
            let pos = journal.append(&test_digest(3)).await.unwrap();
            assert_eq!(pos, 3);
            journal.sync().await.unwrap();
            drop(journal);

            // All of it persists across a reopen.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..4);
            assert_eq!(journal.read(3).await.unwrap(), test_digest(3));

            // Clearing to u64::MAX is rejected.
            let mut journal = journal;
            assert!(matches!(
                journal.clear_to_size(u64::MAX).await,
                Err(Error::SizeOverflow)
            ));

            journal.destroy().await.unwrap();
        });
    }

    /// The cleared image (both clear paths) is durable when `clear_to_size` returns.
    #[test_traced]
    fn test_fixed_journal_clear_to_size_durable_without_sync() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
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
            let cfg = test_cfg(&context);
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 5..5);
            journal.destroy().await.unwrap();
        });
    }

    /// A below-boundary clear removes the partition (one commit) and recreates the blob (a
    /// second commit): the module docs claim a crash between the two recovers an EMPTY
    /// journal at position 0, never fabricated items. Pin that claim by constructing the
    /// intermediate state directly — the partition removed, nothing recreated — and then
    /// re-clearing to the intended target the way the sync flows do on reopen.
    #[test_traced]
    fn test_fixed_journal_recreate_crash_window_recovery() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.prune(5).await.unwrap();
            assert_eq!(journal.bounds(), 5..10);
            drop(journal);

            // The crash window's intermediate state: a below-boundary clear (to 3) has
            // committed its removal but not the recreated image.
            context.remove(&cfg.partition, None).await.unwrap();

            // Recovery: the journal comes up EMPTY at position 0.
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            assert!(matches!(
                journal.read(0).await,
                Err(Error::ItemOutOfRange(0))
            ));

            // A qmdb-sync-style re-clear to the intended target succeeds (see
            // qmdb/sync/journal.rs and test_sync_journal_new_reclears_to_earlier_start).
            journal.clear_to_size(3).await.unwrap();
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            assert_eq!(bounds.start, 3);
            let pos = journal.append(&test_digest(3)).await.unwrap();
            assert_eq!(pos, 3);
            journal.sync().await.unwrap();
            drop(journal);

            // The re-cleared image persists across a plain reopen.
            let journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 3..4);
            assert_eq!(journal.read(3).await.unwrap(), test_digest(3));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_destroy_and_reinit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.prune(5).await.unwrap();
            journal.destroy().await.unwrap();

            // Destroy removes the partition wholesale: a reinit starts fresh.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..0);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_and_probe_parity() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..100 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.prune(10).await.unwrap();

            // Empty input.
            assert!(journal.read_many(&[]).await.unwrap().is_empty());

            // Mixed cached/uncached batch matches point reads.
            let positions: Vec<u64> = vec![10, 11, 37, 63, 99];
            let items = journal.read_many(&positions).await.unwrap();
            for (pos, item) in positions.iter().zip(&items) {
                assert_eq!(*item, journal.read(*pos).await.unwrap());
            }

            // Pruned and out-of-range positions fail.
            assert!(matches!(
                journal.read_many(&[9, 10]).await,
                Err(Error::ItemPruned(9))
            ));
            assert!(matches!(
                journal.read_many(&[99, 100]).await,
                Err(Error::ItemOutOfRange(100))
            ));

            // The sync probe serves cache hits and declines the rest; pruned/out-of-range
            // positions decline to None instead of failing.
            let probe: Vec<u64> = vec![5, 10, 37, 99, 150];
            let probed = journal.try_read_many_sync(&probe);
            assert_eq!(probed.len(), probe.len());
            assert!(probed[0].is_none());
            assert!(probed[4].is_none());
            for (slot, &pos) in probed.iter().zip(&probe) {
                if let Some(item) = slot {
                    assert_eq!(*item, journal.read(pos).await.unwrap());
                }
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_rejects_unsorted_positions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            let result = std::panic::AssertUnwindSafe(journal.read_many(&[3, 1]))
                .catch_unwind()
                .await;
            assert!(result.is_err());

            let result = std::panic::AssertUnwindSafe(journal.read_many(&[3, 3]))
                .catch_unwind()
                .await;
            assert!(result.is_err());

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0u64..7 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            journal.prune(2).await.unwrap();
            journal.read(3).await.unwrap();

            let buffer = context.encode();
            assert_eq!(counter(&buffer, "append_calls_total"), 7);
            assert_eq!(counter(&buffer, "sync_calls_total"), 1);
            assert_eq!(counter(&buffer, "read_calls_total"), 1);
            assert!(buffer.contains("size 7"));
            assert!(buffer.contains("pruning_boundary 2"));
            assert!(buffer.contains("retained 5"));

            journal.destroy().await.unwrap();
        });
    }

    /// An unsynced append is discarded by a crash while synced items survive, and the journal
    /// recovers cleanly (backend syncs are atomic: no partial item can survive).
    #[test_traced]
    fn test_fixed_journal_crash_discards_unsynced_appends() {
        let executor = deterministic::Runner::default();
        let (_, state) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..10 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            for i in 10u64..20 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            // No sync for the second half.
        });

        deterministic::Runner::from(state).start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 10);
            for i in 0u64..10 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            // Appends continue from the recovered size.
            let pos = journal.append(&test_digest(10)).await.unwrap();
            assert_eq!(pos, 10);
            journal.destroy().await.unwrap();
        });
    }

    /// Interleave appends, exact prunes, and syncs over many cycles, then reopen: the blob's
    /// committed checksum coverage must hydrate cleanly whatever the floor's chunk phase.
    #[test_traced]
    fn test_fixed_journal_many_prune_sync_cycles_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            let mut appended = 0u64;
            for i in 0..300u64 {
                for _ in 0..19 {
                    journal.append(&test_digest(appended)).await.unwrap();
                    appended += 1;
                }
                journal.prune((i * 19).min(appended)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 299 * 19..300 * 19);

            // Fully prune (dropping every committed checksum ref), append into the floor's
            // chunk, and sync: the next reopen must still hydrate (pins the delta-capture
            // restart at the floor's chunk).
            journal.prune(appended).await.unwrap();
            assert!(journal.bounds().is_empty());
            for _ in 0..3 {
                journal.append(&test_digest(appended)).await.unwrap();
                appended += 1;
            }
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 300 * 19..300 * 19 + 3);
            journal.destroy().await.unwrap();
        });
    }

    /// Append many across page boundaries in one call, including the nested shape.
    #[test_traced]
    fn test_fixed_journal_append_many_shapes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context);
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            let first: Vec<Digest> = (0u64..75).map(test_digest).collect();
            let second: Vec<Digest> = (75u64..100).map(test_digest).collect();
            let pos = journal
                .append_many(Many::Nested(&[&first, &second]))
                .await
                .unwrap();
            assert_eq!(pos, 99);

            // Prepared appends land identically.
            let third: Vec<Digest> = (100u64..110).map(test_digest).collect();
            let prepared = journal.prepare_append(Many::Flat(&third));
            let pos = journal.append_prepared(prepared).await.unwrap();
            assert_eq!(pos, 109);

            for i in 0u64..110 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.destroy().await.unwrap();
        });
    }
}
