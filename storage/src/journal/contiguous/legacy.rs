//! The legacy multi-blob fixed-item journal, retained as the [super::variable] journal's
//! offsets index until that journal moves to the single-blob layout.
//!
//! [super::fixed] replaced this implementation for direct consumers: it stores all items in
//! ONE blob and prunes with the runtime's native [commonware_runtime::Blob::prune]. The
//! variable journal still composes this implementation (its section-aligned data blobs and
//! this offsets journal roll over and prune in lockstep), so the multi-blob machinery lives
//! on here, unchanged, until the variable journal's own rework.
//!
//! In addition to replay, stored items can be fetched directly by their `position` in the journal,
//! where position is defined as the item's order of insertion starting from 0, unaffected by
//! pruning.
//!
//! # Format
//!
//! Data stored in a `fixed::Journal` is persisted in one of many Blobs. Each `Blob` contains a
//! configurable maximum of `items_per_blob`, with page-level data integrity provided by a buffer
//! pool.
//!
//! ```text
//! +--------+--------+-----+----------+
//! | item_0 | item_1 | ... | item_n-1 |
//! +--------+--------+-----+----------+
//!
//! n = config.items_per_blob
//! ```
//!
//! The most recent blob may not necessarily be full, in which case it will contain fewer than the
//! maximum number of items.
//!
//! # Architecture
//!
//! Three types divide the work:
//!
//! - [`Journal`] tracks which positions are readable (`bounds`), maps each position to a blob
//!   and byte offset, and remembers which blobs have writes that are not yet fsynced
//!   (`dirty_from_blob`) so sync only fsyncs what changed.
//!
//! - `Writable` owns the files: the contiguous sealed blobs plus the one writable tail.
//!
//! - `Checkpoint` owns the durable recovery hint (a mid-blob pruning boundary) consulted
//!   before trusting blob state on startup.
//!
//! # Open Blobs
//!
//! Every retained blob is held open; a pruned blob stays open until the last snapshot holding it
//! drops. Use a larger `items_per_blob` or prune to bound the count.
//!
//! # Partition
//!
//! Blobs are stored in the legacy partition (`cfg.partition`) if it already contains data;
//! otherwise they are stored in `{cfg.partition}-blobs`.
//!
//! The checkpoint (the durable recovery record: a pruning boundary that blob state cannot
//! derive) is stored in `{cfg.partition}-metadata`.
//!
//! # Recovery
//!
//! The storage backend restores every blob to exactly its last-synced state after a crash, so
//! recovery is verification, not repair. A rollover commits the filled blob's durability and
//! the next blob's creation in ONE batch (see `Writable::seal_tail_into`), so "a blob exists"
//! implies "every older blob is full and durable" atomically, by construction. Recovery walks
//! the blob range from oldest to newest and checks each blob's byte length: every blob must
//! hold whole items, every non-newest blob must be exactly full, and the newest blob (the
//! append frontier) may be short. Any violation is corruption.
//!
//! # Consistency
//!
//! Data written to `Journal` may not be immediately persisted to `Storage`. It is up to the caller
//! to determine when to force pending data to be durably written using `sync`.
//!
//! # Pruning
//!
//! The `prune` method allows the `Journal` to prune blobs consisting entirely of items prior to a
//! given point in history. The blob removals and the boundary record land in ONE batch, so a
//! crash leaves the journal either unpruned or fully pruned.
//!
//! # Clearing / reset
//!
//! Clearing wipes all data and restarts the journal at a new size.
//!
//! To stay crash-safe, a clear records its target size in the checkpoint in the SAME batch as
//! the blob removals. If a crash lands after the batch, reopening sees the recorded target and
//! recovers the cleared journal.
//!
//! Callers reach this through `clear_to_size` (clear an open journal) or `init_at_size` (open
//! straight into a cleared, empty journal at a given size).
//!
//! # Replay
//!
//! The `replay` method supports fast reading of all unpruned items into memory.

use super::{
    blobs::{Blob, Blobs, Partition, Replay as BlobReplay, Writable},
    checkpoint::Checkpoint,
};
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
use futures::{future::try_join_all, Stream};
use std::{
    collections::BTreeMap,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::Arc,
};

// Reusable scratch for [`Reader::probe_items`], grown to the largest probe served on the
// thread. Probes run per shard on the hot read path, where a fresh zeroed allocation per call
// contends under the pool's fan-out.
commonware_utils::thread_local_cache!(static PROBE_SCRATCH: Vec<u8>);

/// Items encoded for a deferred append, created by [`Journal::prepare_append`] and consumed
/// by the append paths.
pub struct PreparedAppend<A> {
    buf: Vec<u8>,
    _marker: PhantomData<A>,
}

/// Return the first retained logical position in `blob`.
#[inline]
fn first_in_blob(pruning_boundary: u64, blob: u64, items_per_blob: u64) -> Result<u64, Error> {
    let start = super::blob_first_position(blob, items_per_blob)?;
    Ok(pruning_boundary.max(start))
}

/// Build a replay stream over the retained blob range.
///
/// The stream is split into one state per blob so replay can start at a mid-blob pruning boundary,
/// stop at the journal's logical end, and avoid reading across blob files. `buffer` is a byte
/// budget for each blob replay, not an item count.
fn replay_stream<'a, B: RBlob, A: CodecFixedShared>(
    blobs: &Blobs<'a, B>,
    bounds: Range<u64>,
    items_per_blob: NonZeroU64,
    start_pos: u64,
    buffer: NonZeroUsize,
) -> Result<impl Stream<Item = Result<(u64, A), Error>> + Send + use<'a, B, A>, Error> {
    if start_pos > bounds.end {
        return Err(Error::ItemOutOfRange(start_pos));
    }
    if start_pos < bounds.start {
        return Err(Error::ItemPruned(start_pos));
    }

    let mut states = Vec::new();
    if start_pos < bounds.end {
        let items_per_blob = items_per_blob.get();
        let start_blob = super::position_to_blob(start_pos, items_per_blob);
        let end_blob = super::position_to_blob(bounds.end - 1, items_per_blob);
        let items_per_batch = (buffer.get() / A::SIZE).max(1);

        for blob in start_blob..=end_blob {
            // The oldest retained blob may begin after its natural blob boundary when pruning
            // kept only a suffix.
            let blob_first = first_in_blob(bounds.start, blob, items_per_blob)?;
            let first_pos = if blob == start_blob {
                start_pos
            } else {
                blob_first
            };
            let blob_end = super::blob_end_position(blob, items_per_blob, bounds.end);
            let offset = (first_pos - blob_first)
                .checked_mul(A::SIZE as u64)
                .ok_or(Error::OffsetOverflow)?;
            let blob = blobs
                .get(blob)
                .expect("positions in bounds map to a retained blob");

            states.push(FixedReplayState::<B, A> {
                replay: blob.replay_from(offset, buffer)?,
                pos: first_pos,
                end_pos: blob_end,
                items_per_batch,
                _marker: PhantomData,
            });
        }
    }

    Ok(super::replay_stream_from_states(states))
}

/// Replay state for one fixed-size blob.
struct FixedReplayState<'a, B: RBlob, A> {
    /// Sequential logical bytes for this blob.
    replay: BlobReplay<'a, B>,
    /// Next position to yield.
    pos: u64,
    /// Exclusive end position within this blob.
    end_pos: u64,
    /// Maximum number of items decoded per stream poll.
    items_per_batch: usize,
    _marker: PhantomData<A>,
}

impl<B: RBlob, A: CodecFixedShared> super::ReplayBatchState for FixedReplayState<'_, B, A> {
    type Item = A;

    /// Decode the next batch of fixed-size items from this blob.
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

        // Decode only whole items that are already buffered, capped by the replay byte budget and
        // this blob's logical end.
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
    /// Prefix for the journal partitions.
    ///
    /// Blobs are stored in `partition` (legacy) if it contains data, otherwise in
    /// `{partition}-blobs`. Metadata is stored in `{partition}-metadata`.
    pub partition: String,

    /// The maximum number of journal items to store in each blob.
    ///
    /// Retained non-tail blobs are expected to be full relative to their logical capacity. A
    /// mid-blob oldest blob may physically hold fewer than this many items, and the newest blob
    /// may contain fewer items.
    pub items_per_blob: NonZeroU64,

    /// The page cache to use for caching data.
    pub page_cache: CacheRef,

    /// The size of the write buffer to use for each blob.
    pub write_buffer: NonZeroUsize,
}

/// Implementation of [super::Mutable] for fixed-size value journals.
///
/// # Recovery
///
/// The storage backend guarantees per-blob atomic sync, so torn or trailing partial writes
/// cannot survive a crash. Recovery verifies blob lengths against their capacities and returns
/// [Error::Corruption] on any violation instead of repairing.
pub struct Journal<E: Context, A> {
    /// The blobs that comprise the journal.
    blobs: Writable<E>,

    /// The durable recovery checkpoint.
    checkpoint: Checkpoint<E>,

    /// The readable positions; `bounds.end` is the next append position.
    bounds: Range<u64>,

    /// Earliest blob modified since the last `sync()`.
    dirty_from_blob: Option<u64>,

    /// The maximum number of items per blob.
    items_per_blob: NonZeroU64,

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

    /// Mark all blobs from `blob` onward as dirty.
    fn mark_dirty_from(&mut self, blob: u64) {
        self.dirty_from_blob = Some(
            self.dirty_from_blob
                .map_or(blob, |existing| existing.min(blob)),
        );
    }

    /// Construct a journal from recovered blobs.
    fn from_blobs(
        blobs: Writable<E>,
        checkpoint: Checkpoint<E>,
        bounds: Range<u64>,
        dirty_from_blob: Option<u64>,
        items_per_blob: NonZeroU64,
        metrics: Metrics<E>,
    ) -> Self {
        Self {
            blobs,
            checkpoint,
            bounds,
            dirty_from_blob,
            items_per_blob,
            metrics: Arc::new(metrics),
            _phantom: PhantomData,
        }
    }

    /// Initialize a new `Journal` instance.
    ///
    /// All backing blobs are opened but not read during initialization. The `replay` method can be
    /// used to iterate over all items in the `Journal`.
    pub async fn init(context: E, cfg: Config) -> Result<Self, Error> {
        let checkpoint = Checkpoint::open(context.child("meta"), &cfg.partition).await?;
        Self::init_with_checkpoint(context, cfg, checkpoint).await
    }

    /// Finish initialization using an already-open checkpoint.
    async fn init_with_checkpoint(
        context: E,
        cfg: Config,
        checkpoint: Checkpoint<E>,
    ) -> Result<Self, Error> {
        let blob_partition = Partition::select(&context, &cfg.partition).await?;
        let partition = Partition::new(
            context.child("blobs"),
            blob_partition,
            cfg.page_cache,
            cfg.write_buffer,
        );
        let pending = partition.open_all().await?;

        let (pruning_boundary, size) = Self::recover_bounds(
            &pending,
            cfg.items_per_blob.get(),
            checkpoint.boundary_hint(),
        )?;

        // Seal every blob below the tail and assemble the blobs.
        let tail_blob = super::position_to_blob(size, cfg.items_per_blob.get());
        let blobs = Writable::recover(partition, pending, tail_blob).await?;

        let metrics = Metrics::new(context);
        metrics.update(size, pruning_boundary, cfg.items_per_blob.get());

        Ok(Self::from_blobs(
            blobs,
            checkpoint,
            pruning_boundary..size,
            None,
            cfg.items_per_blob,
            metrics,
        ))
    }

    /// Recover the journal bounds from the checkpoint and blob state.
    ///
    /// A mid-blob boundary hint referencing anything but the oldest blob, or an invalid blob
    /// length, is corruption.
    fn recover_bounds(
        pending: &BTreeMap<u64, Writer<E::Blob>>,
        items_per_blob: u64,
        boundary_hint: Option<u64>,
    ) -> Result<(u64, u64), Error> {
        let pruning_boundary = Self::recover_pruning_boundary(
            boundary_hint,
            pending.keys().next().copied(),
            items_per_blob,
        )?;

        let size = Self::verify_blob_lengths(pending, items_per_blob, pruning_boundary)?;

        Ok((pruning_boundary, size))
    }

    /// Recover the pruning boundary from the checkpoint hint if it still matches the oldest
    /// retained blob.
    ///
    /// A missing or blob-aligned hint means the blob boundary is authoritative. A mid-blob hint
    /// must belong to the current oldest blob: prune stages its blob removals and boundary
    /// record in one batch, and a clear removes every blob in the same batch as its record, so
    /// a hint referencing any other blob cannot arise and is corruption.
    fn recover_pruning_boundary(
        boundary_hint: Option<u64>,
        oldest_blob: Option<u64>,
        items_per_blob: u64,
    ) -> Result<u64, Error> {
        let blob_boundary = match oldest_blob {
            Some(oldest) => super::blob_first_position(oldest, items_per_blob)?,
            None => 0,
        };

        let Some(boundary_hint) = boundary_hint else {
            return Ok(blob_boundary);
        };
        let Some(oldest_blob) = oldest_blob else {
            // No blobs with a hint is the cleared state: the clear's batch removed every
            // blob and recorded the target as the boundary; the new tail blob is recreated
            // by this open.
            return Ok(boundary_hint);
        };
        if boundary_hint.is_multiple_of(items_per_blob) {
            return Ok(blob_boundary);
        }

        let hint_blob = super::position_to_blob(boundary_hint, items_per_blob);
        if hint_blob == oldest_blob {
            Ok(boundary_hint)
        } else {
            Err(Error::Corruption(format!(
                "boundary hint references blob {hint_blob} \
                 but oldest blob is blob {oldest_blob}"
            )))
        }
    }

    /// Verify blob lengths from oldest to newest and return the recovered size.
    ///
    /// A rollover commits a filled blob's durability atomically with its successor's creation,
    /// and the backend restores every blob to its last-synced state, so lengths are checkable
    /// facts: every blob must hold whole items, every non-newest blob must be exactly full
    /// (relative to its capacity), and the newest blob may be short. Any violation is
    /// corruption.
    fn verify_blob_lengths(
        pending: &BTreeMap<u64, Writer<E::Blob>>,
        items_per_blob: u64,
        pruning_boundary: u64,
    ) -> Result<u64, Error> {
        let oldest = pending.keys().next().copied();
        let newest = pending.keys().next_back().copied();

        let (Some(oldest), Some(newest)) = (oldest, newest) else {
            return Ok(pruning_boundary);
        };

        let mut size = pruning_boundary;
        for blob in oldest..=newest {
            // A missing interior blob counts as zero bytes and fails the fullness check below.
            let bytes = pending.get(&blob).map_or(0, |writer| writer.size());
            if !bytes.is_multiple_of(Self::CHUNK_SIZE_U64) {
                return Err(Error::Corruption(format!(
                    "blob {blob} has a partial item: {bytes} bytes"
                )));
            }
            let len = bytes / Self::CHUNK_SIZE_U64;

            // A blob's capacity is `items_per_blob`, unless the pruning boundary falls mid-blob
            // (from `init_at_size`), in which case the skipped prefix reduces it.
            let start = super::blob_first_position(blob, items_per_blob)?;
            let skipped = pruning_boundary.saturating_sub(start).min(items_per_blob);
            let capacity = items_per_blob - skipped;

            if len > capacity {
                return Err(Error::Corruption(format!(
                    "blob {blob} has too many items: expected at most {capacity}, got {len}"
                )));
            }
            if len < capacity && blob != newest {
                return Err(Error::Corruption(format!(
                    "blob {blob} is short: expected {capacity} items, got {len}"
                )));
            }
            size = size.checked_add(len).ok_or(Error::OffsetOverflow)?;
        }

        Ok(size)
    }

    /// Initialize a `Journal` in a fully-pruned state at `size`: existing data is cleared and the
    /// journal behaves as if `size` items were appended then pruned. It is empty (`bounds` is
    /// `size..size`) and the next `append` writes at position `size`. Used for state sync.
    ///
    /// # Crash Safety
    /// In the event of a crash during this call, upon restart recovery will ensure the journal is
    /// either still in its prior state, or has bounds `size..size`.
    ///
    /// Test-only: the variable journal resets through [Self::stage_reset] directly.
    #[cfg(test)]
    pub async fn init_at_size(context: E, cfg: Config, size: u64) -> Result<Self, Error> {
        // A journal sized at `u64::MAX` can never accept an append (the successor size
        // overflows), so reject it before removing anything.
        if size == u64::MAX {
            return Err(Error::SizeOverflow);
        }

        // Fail before mutating if existing blob partitions are already inconsistent.
        Partition::select(&context, &cfg.partition).await?;

        // One batch resets everything: every blob partition removal plus the cleared-boundary
        // record. The reset is old-state-or-new-state; init then recovers the cleared journal
        // (a boundary hint with no blobs) and recreates the tail.
        let mut checkpoint = Checkpoint::open(context.child("meta"), &cfg.partition).await?;
        let mut batch = context.batch().await.map_err(Error::Runtime)?;
        Self::stage_reset(&context, &cfg.partition, &mut checkpoint, size, &mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)?;

        Self::init_with_checkpoint(context, cfg, checkpoint).await
    }

    /// Stage a reset of this journal's persisted state with `batch`: the removal of every blob
    /// partition plus the cleared-boundary record. The caller applies the batch and re-opens.
    #[commonware_macros::stability(ALPHA)]
    pub(in crate::journal::contiguous) async fn stage_reset(
        context: &E,
        prefix: &str,
        checkpoint: &mut Checkpoint<E>,
        target: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        // TODO(#2941): Remove legacy partition support
        let new_partition = format!("{prefix}-blobs");
        for partition in [prefix, new_partition.as_str()] {
            match context.scan(partition).await {
                Ok(_) => batch.remove(partition, None),
                Err(commonware_runtime::Error::PartitionMissing(_)) => {}
                Err(err) => return Err(Error::Runtime(err)),
            }
        }
        checkpoint.clear_into(target, batch).await
    }

    /// The storage context the journal operates on.
    pub(crate) const fn context(&self) -> &E {
        self.blobs.context()
    }

    /// Stage the durability of every dirty blob and the checkpoint's pruning
    /// boundary with `batch`, so blob data and the boundary record land in
    /// ONE batch.
    ///
    /// Dirty tracking resets immediately: the caller must apply the batch
    /// (storage failures are fatal, so an abandoned batch has no recovery
    /// path anyway).
    pub(crate) async fn sync_into(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        if let Some(start_blob) = self.dirty_from_blob {
            self.blobs.sync_from_into(start_blob, batch).await?;
            self.dirty_from_blob = None;
        }
        self.persist_boundary_into(batch).await
    }

    /// Stage the checkpoint's boundary record with `batch`. A blob-aligned boundary is
    /// derived from the oldest blob, so the hint is kept only while the boundary is
    /// mid-blob.
    async fn persist_boundary_into(&mut self, batch: &mut E::Batch) -> Result<(), Error> {
        let boundary = self.bounds.start;
        let hint = (!boundary.is_multiple_of(self.items_per_blob.get())).then_some(boundary);
        self.checkpoint.persist_into(hint, batch).await
    }

    /// Durably persist the current state of the structure, including the checkpoint's pruning
    /// boundary — one batch, so the data and the boundary record commit together with a
    /// single sync.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        self.sync_into(&mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// Capture an owned snapshot ([`Reader`]) over the current journal. Bounds are frozen at
    /// creation, and the snapshot stays readable across concurrent appends and prunes.
    ///
    /// If the journal later rewinds or truncates into the returned reader's range, subsequent reads
    /// from that range may observe unspecified contents.
    pub async fn snapshot(&mut self) -> Result<Reader<'static, E, A>, Error> {
        Ok(Reader {
            blobs: self.blobs.snapshot().await?,
            bounds: self.bounds.clone(),
            items_per_blob: self.items_per_blob,
            metrics: self.metrics.clone(),
            _phantom: PhantomData,
        })
    }

    /// A reader borrowing the journal's live state.
    pub(super) fn reader(&self) -> Reader<'_, E, A> {
        Reader {
            blobs: self.blobs.reader(),
            bounds: self.bounds.clone(),
            items_per_blob: self.items_per_blob,
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

    /// Encode `items` into a buffer the append paths can write later.
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

    // Write pre-encoded items; shared by all append paths. Records no call metrics.
    async fn write_encoded(&mut self, prepared: PreparedAppend<A>) -> Result<u64, Error> {
        self.write_encoded_inner(prepared, None).await
    }

    /// Append items, staging any blob rollover with the caller's `batch` instead of committing
    /// it: the filled tail's durability, its successor's creation, and everything else the
    /// caller stages land in ONE commit. The caller must apply the batch before any further
    /// append, so the items must end exactly at (or before) the tail blob's boundary.
    pub(in crate::journal::contiguous) async fn append_many_into<'a>(
        &'a mut self,
        items: Many<'a, A>,
        batch: &mut E::Batch,
    ) -> Result<u64, Error> {
        let prepared = self.prepare_append(items);
        self.write_encoded_inner(prepared, Some(batch)).await
    }

    // Write pre-encoded items. A rollover stages the filled tail's durability and its
    // successor's creation in one batch: `rollover` when provided (the caller applies it),
    // otherwise a batch built and committed here.
    async fn write_encoded_inner(
        &mut self,
        prepared: PreparedAppend<A>,
        mut rollover: Option<&mut E::Batch>,
    ) -> Result<u64, Error> {
        let items_buf = prepared.buf;
        let items_count = items_buf.len() / A::SIZE;
        if items_count == 0 {
            return Err(Error::EmptyAppend);
        }
        let items_buf = IoBuf::from(items_buf);

        // Reject the append before writing anything if it would push the size past `u64::MAX`.
        // This keeps the in-loop size arithmetic safe.
        self.bounds
            .end
            .checked_add(items_count as u64)
            .ok_or(Error::SizeOverflow)?;

        let first_dirty_blob = super::position_to_blob(self.bounds.end, self.items_per_blob.get());
        self.mark_dirty_from(first_dirty_blob);
        let mut written = 0;
        while written < items_count {
            let batch_count = super::batch_count_to_blob_boundary(
                self.bounds.end,
                items_count - written,
                self.items_per_blob.get(),
            );
            let start = written * A::SIZE;
            let end = start + batch_count * A::SIZE;
            // Overflow checked above.
            let new_size = self.bounds.end + batch_count as u64;

            self.blobs
                .tail_writer()
                .append_owned(items_buf.slice(start..end))
                .await
                .map_err(Error::Runtime)?;
            self.bounds.end = new_size;
            written += batch_count;

            // Roll over the just-filled tail: its durability and the successor's creation are
            // ONE commit, so every blob below the new tail is durable once that commit lands
            // and dirty tracking restarts there.
            if new_size.is_multiple_of(self.items_per_blob.get()) {
                match rollover.as_deref_mut() {
                    Some(batch) => {
                        self.blobs.seal_tail_into(batch).await?;
                        // The caller applies the batch. Until then the new tail's creation is
                        // unpublished, so no further items may be written.
                        assert!(
                            written == items_count,
                            "a staged rollover must end the append"
                        );
                    }
                    None => {
                        let mut batch =
                            self.blobs.context().batch().await.map_err(Error::Runtime)?;
                        self.blobs.seal_tail_into(&mut batch).await?;
                        batch.apply_sync().await.map_err(Error::Runtime)?;
                    }
                }
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

    /// Rewind the journal to the given `size`. Returns [Error::InvalidRewind] if `size` is beyond
    /// the current size, or [Error::ItemPruned] if it precedes the pruning boundary. The journal
    /// is not synced after rewinding.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until `sync()` is
    ///   called.
    /// * This operation is not atomic. Its on-disk updates are ordered (blobs removed
    ///   newest-to-oldest) so that restart recovery always rebuilds a contiguous retained prefix.
    /// * Readers returned by [`snapshot`](Self::snapshot) may observe unspecified contents if this
    ///   rewind truncates into their range.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.bounds.end) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        if size < self.bounds.start {
            return Err(Error::ItemPruned(size));
        }

        let blob = super::position_to_blob(size, self.items_per_blob.get());
        let pos_in_blob = size - first_in_blob(self.bounds.start, blob, self.items_per_blob.get())?;
        let byte_offset = Self::items_to_bytes(pos_in_blob)?;

        if blob == self.blobs.tail_blob_index() {
            self.blobs.rewind_tail(byte_offset).await?;
        } else {
            self.blobs.rewind_into_sealed(blob, byte_offset).await?;
        }

        self.bounds.end = size;
        self.mark_dirty_from(blob);
        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );

        Ok(())
    }

    /// Rewind the journal to `size`, staging every mutation (the rewound blob's truncation and
    /// the removal of newer blobs) with `batch`: the whole rewind publishes and becomes durable
    /// when the caller applies the batch, atomically with everything else it stages.
    ///
    /// Validation errors match [Self::rewind].
    pub(in crate::journal::contiguous) async fn rewind_into(
        &mut self,
        size: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        match size.cmp(&self.bounds.end) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        if size < self.bounds.start {
            return Err(Error::ItemPruned(size));
        }

        let blob = super::position_to_blob(size, self.items_per_blob.get());
        let pos_in_blob = size - first_in_blob(self.bounds.start, blob, self.items_per_blob.get())?;
        let byte_offset = Self::items_to_bytes(pos_in_blob)?;

        if blob == self.blobs.tail_blob_index() {
            self.blobs.rewind_tail_into(byte_offset, batch).await?;
        } else {
            self.blobs
                .rewind_into_sealed_into(blob, byte_offset, batch)
                .await?;
        }

        self.bounds.end = size;
        self.mark_dirty_from(blob);
        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );

        Ok(())
    }

    /// Return the location before which all items have been pruned.
    pub const fn pruning_boundary(&self) -> u64 {
        self.bounds.start
    }

    /// Allow the journal to prune items older than `min_item_pos`. The journal may not prune all
    /// such items in order to preserve blob boundaries, but the amount of such items will always be
    /// less than the configured number of items per blob. Returns true if any items were pruned.
    ///
    /// Readers holding earlier snapshots keep reading pruned blobs through their own handles;
    /// later snapshots observe [Error::ItemPruned].
    ///
    /// The dirty retained blobs, the blob removals, and the boundary record land in ONE batch,
    /// so the prune is old-state-or-new-state.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<bool, Error> {
        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        if !self.prune_into(min_item_pos, &mut batch).await? {
            return Ok(false);
        }
        batch.apply_sync().await.map_err(Error::Runtime)?;
        Ok(true)
    }

    /// Stage a prune with `batch`: the caller applies the batch. Returns true if a prune
    /// was staged.
    pub(crate) async fn prune_into(
        &mut self,
        min_item_pos: u64,
        batch: &mut E::Batch,
    ) -> Result<bool, Error> {
        // Calculate the blob that would contain min_item_pos, capped to the tail (which is
        // guaranteed to exist by our invariant).
        let target_blob = super::position_to_blob(min_item_pos, self.items_per_blob.get());
        let tail_blob = super::position_to_blob(self.bounds.end, self.items_per_blob.get());
        let min_blob = std::cmp::min(target_blob, tail_blob);

        if min_blob <= self.blobs.oldest_blob_index() {
            return Ok(false);
        }

        // Stage the durability of dirty retained blobs with the same batch: the prune target
        // may be justified by an appended-but-unflushed item (e.g. a consumer's commit
        // record), and the removals must not become durable without it. Dirty blobs below the
        // prune point need no staging: the batch removes them.
        if let Some(dirty) = self.dirty_from_blob {
            self.blobs
                .sync_from_into(dirty.max(min_blob), batch)
                .await?;
            self.dirty_from_blob = None;
        }

        self.bounds.start = super::blob_first_position(min_blob, self.items_per_blob.get())?;
        self.persist_boundary_into(batch).await?;
        self.blobs.prune_into(min_blob, batch);

        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );

        Ok(true)
    }

    /// Remove any persisted data created by the journal: the data partition's removal and
    /// the checkpoint's land in ONE atomic commit, so destruction is all-or-nothing.
    pub async fn destroy(self) -> Result<(), Error> {
        let mut batch = self.context().batch().await.map_err(Error::Runtime)?;
        self.destroy_into(&mut batch);
        batch.apply_sync().await.map_err(Error::Runtime)
    }

    /// [Self::destroy], staged with `batch`: both partition removals land when the caller
    /// applies the batch with `apply_sync`, atomically with everything else it stages.
    pub(crate) fn destroy_into(self, batch: &mut E::Batch) {
        self.blobs.stage_destroy(batch);
        self.checkpoint.destroy_into(batch);
    }

    /// Clear all data and reset the journal to a new starting position.
    ///
    /// Unlike `destroy`, this keeps the journal alive so it can be reused. After clearing, the
    /// journal will behave as if initialized with `init_at_size(new_size)`.
    ///
    /// # Crash Safety
    ///
    /// The blob removals and the cleared-boundary record land in ONE batch: a crash leaves
    /// the journal either in its prior state or with bounds `new_size..new_size`.
    ///
    /// Test-only: the variable journal clears through [Self::stage_clear] and
    /// [Self::finish_clear] directly.
    #[cfg(test)]
    pub(crate) async fn clear_to_size(&mut self, new_size: u64) -> Result<(), Error> {
        // A journal sized at `u64::MAX` can never accept an append, matching `init_at_size`.
        if new_size == u64::MAX {
            return Err(Error::SizeOverflow);
        }

        let mut batch = self.blobs.context().batch().await.map_err(Error::Runtime)?;
        self.stage_clear(new_size, &mut batch).await?;
        batch.apply_sync().await.map_err(Error::Runtime)?;
        self.finish_clear(new_size).await
    }

    /// Stage this journal's clear with `batch`: every tracked blob removal plus the
    /// cleared-boundary record. The caller applies the batch, then resets RAM state with
    /// [Self::finish_clear].
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn stage_clear(
        &mut self,
        new_size: u64,
        batch: &mut E::Batch,
    ) -> Result<(), Error> {
        self.blobs.stage_clear(batch);
        self.checkpoint.clear_into(new_size, batch).await
    }

    /// Reset RAM state to the cleared journal and open the new tail (the staged clear must
    /// have been applied).
    #[commonware_macros::stability(ALPHA)]
    pub(crate) async fn finish_clear(&mut self, new_size: u64) -> Result<(), Error> {
        self.blobs
            .finish_clear(super::position_to_blob(new_size, self.items_per_blob.get()))
            .await?;
        self.bounds = new_size..new_size;
        self.dirty_from_blob = None;
        self.metrics.update(
            self.bounds.end,
            self.bounds.start,
            self.items_per_blob.get(),
        );
        Ok(())
    }
}

/// A reader over a fixed journal.
pub struct Reader<'a, E: Context, A> {
    blobs: Blobs<'a, E::Blob>,
    bounds: Range<u64>,
    items_per_blob: NonZeroU64,
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

    /// Resolve a blob-sharing group of positions to its blob number and per-position byte
    /// offsets within the blob.
    fn locate_group(&self, group: &[u64]) -> Result<(u64, Vec<u64>), Error> {
        let items_per_blob = self.items_per_blob.get();
        let blob = super::position_to_blob(group[0], items_per_blob);
        let first_position = first_in_blob(self.bounds.start, blob, items_per_blob)?;
        let offsets = group
            .iter()
            .map(|&pos| Journal::<E, A>::items_to_bytes(pos - first_position))
            .collect::<Result<Vec<u64>, _>>()?;
        Ok((blob, offsets))
    }

    /// Shared body of [`super::Contiguous::read_many`] and the variable journal's offsets
    /// reads; the callers record the batch-read metrics, so routing them through `read_many`
    /// would count every batch twice.
    pub(super) async fn read_many_inner(&self, positions: &[u64]) -> Result<Vec<A>, Error> {
        if positions.is_empty() {
            return Ok(Vec::new());
        }
        assert!(
            positions.is_sorted_by(|a, b| a < b),
            "positions must be strictly increasing"
        );
        for &pos in positions {
            self.validate_readable(pos)?;
        }

        let items_per_blob = self.items_per_blob.get();

        // Read all positions grouped by blob. Positions are sorted, so `chunk_by` splits them into
        // maximal runs that share one blob. Each group goes through the blob's batched read,
        // which serves page-cache and tip-buffer hits under a single lock acquisition and reads only
        // true misses from the blob (concurrently).
        let mut result: Vec<A> = Vec::with_capacity(positions.len());
        let mut reusable_buf = vec![0u8; positions.len() * A::SIZE];

        // The buffer is pre-sized for every position, so each group can own a disjoint slice and
        // all groups can read concurrently.
        let mut reads = Vec::new();
        let mut remaining_buf = reusable_buf.as_mut_slice();
        for group in positions.chunk_by(|a, b| {
            super::position_to_blob(*a, items_per_blob)
                == super::position_to_blob(*b, items_per_blob)
        }) {
            let (blob_num, blob_offsets) = self.locate_group(group)?;
            let blob = self
                .blobs
                .get(blob_num)
                .expect("positions in bounds map to a retained blob");
            let (buf, rest) = remaining_buf.split_at_mut(group.len() * A::SIZE);
            remaining_buf = rest;
            reads.push(async move {
                blob.read_many_into(buf, &blob_offsets, Journal::<E, A>::CHUNK_SIZE)
                    .await
            });
        }
        let hits: u64 = try_join_all(reads)
            .await?
            .into_iter()
            .map(|group_hits| group_hits as u64)
            .sum();

        for slice in reusable_buf.chunks_exact(A::SIZE) {
            result.push(A::decode(slice).map_err(Error::Codec)?);
        }

        self.metrics.cache_hits.inc_by(hits);
        self.metrics
            .cache_misses
            .inc_by(positions.len() as u64 - hits);
        self.metrics.items_read.inc_by(positions.len() as u64);
        Ok(result)
    }

    /// Resolve `pos` to its blob and byte offset within the blob.
    fn locate(&self, pos: u64) -> Result<(Blob<'_, E::Blob>, u64), Error> {
        self.validate_readable(pos)?;
        let items_per_blob = self.items_per_blob.get();
        let blob = super::position_to_blob(pos, items_per_blob);
        let pos_in_blob = pos - first_in_blob(self.bounds.start, blob, items_per_blob)?;
        let offset = Journal::<E, A>::items_to_bytes(pos_in_blob)?;
        let blob = self
            .blobs
            .get(blob)
            .expect("position in bounds maps to a retained blob");
        Ok((blob, offset))
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
        // validation trims the batch instead of poisoning a blob group that also holds valid
        // positions.
        let start = positions.partition_point(|&pos| pos < self.bounds.start);
        let end = positions.partition_point(|&pos| pos < self.bounds.end);
        let valid = &positions[start..end];
        if valid.is_empty() {
            return out;
        }

        // Serve the probe from the per-thread scratch buffer. Stale bytes from a previous probe
        // are harmless: slots the cache cannot serve are reported as misses and never decoded.
        let items_per_blob = self.items_per_blob.get();
        let mut scratch =
            Cached::take(&PROBE_SCRATCH, || Ok::<_, ()>(Vec::new()), |_| Ok(())).unwrap();
        let need = valid.len() * A::SIZE;
        if scratch.len() < need {
            scratch.resize(need, 0);
        }
        let buf = &mut scratch[..need];
        let mut hits = 0u64;
        let mut group_base = start;
        for group in valid.chunk_by(|a, b| {
            super::position_to_blob(*a, items_per_blob)
                == super::position_to_blob(*b, items_per_blob)
        }) {
            let base = group_base;
            group_base += group.len();
            let Ok((blob_num, blob_offsets)) = self.locate_group(group) else {
                continue;
            };
            let Some(blob) = self.blobs.get(blob_num) else {
                continue;
            };
            let buf = &mut buf[..group.len() * A::SIZE];
            let misses =
                blob.try_read_many_sync_into(buf, &blob_offsets, Journal::<E, A>::CHUNK_SIZE);
            let mut misses = misses.into_iter().peekable();
            for (idx, slice) in buf.chunks_exact(A::SIZE).enumerate() {
                if misses.peek() == Some(&idx) {
                    misses.next();
                    continue;
                }
                // A decode failure declines to a miss: the async completion re-reads the
                // item and bubbles the failure as [Error::Codec], like every async read path.
                if let Ok(item) = A::decode(slice) {
                    out[base + idx] = Some(item);
                    hits += 1;
                }
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
        let (blob, offset) = self.locate(pos)?;
        self.metrics.cache_misses.inc();
        let bufs = blob.read_at(offset, A::SIZE).await?;
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
            Ok((blob, offset)) if blob.try_read_sync_into(&mut buf, offset) => {
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
        replay_stream(
            &self.blobs,
            self.bounds.clone(),
            self.items_per_blob,
            start_pos,
            buffer,
        )
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
        let blobs = self.blobs.reader();
        replay_stream(
            &blobs,
            self.bounds.clone(),
            self.items_per_blob,
            start_pos,
            buffer,
        )
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

#[cfg(test)]
mod tests {
    use super::*;
    use crate::journal::contiguous::Contiguous as _;
    use commonware_codec::FixedSize;
    use commonware_cryptography::{sha256::Digest, Hasher as _, Sha256};
    use commonware_macros::test_traced;
    use commonware_runtime::{
        buffer::paged::Writer,
        deterministic::{self, Context},
        Blob, BufferPooler, Error as RuntimeError, Metrics as _, Runner, Spawner as _, Storage,
        Supervisor as _,
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

    /// Extract a metric counter's value from encoded metrics output.
    fn counter(buffer: &str, name: &str) -> u64 {
        buffer
            .lines()
            .find(|l| l.contains(name) && !l.starts_with('#'))
            .and_then(|l| l.split_whitespace().last())
            .and_then(|v| v.parse().ok())
            .expect("counter missing")
    }

    impl<E: crate::Context, A: CodecFixedShared> Journal<E, A> {
        /// Test helper: Get the oldest blob from the blob store.
        pub(crate) const fn test_oldest_blob(&self) -> Option<u64> {
            Some(self.blobs.oldest_blob_index())
        }

        /// Test helper: Get the newest blob from the blob store.
        pub(crate) fn test_newest_blob(&self) -> Option<u64> {
            Some(self.blobs.tail_blob_index())
        }

        /// Test helper: Make one blob durable (sealed history or the tail).
        pub(crate) async fn test_sync_blob(&mut self, blob: u64) -> Result<(), Error> {
            self.blobs.sync_blob(blob).await
        }
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

            // Seed legacy partition (with one whole item) so it is selected.
            let (legacy_blob, _) = context
                .open(&legacy_partition, &0u64.to_be_bytes())
                .await
                .expect("Failed to open legacy blob");
            legacy_blob
                .write_at_sync(0, vec![0u8; Digest::SIZE])
                .await
                .expect("Failed to write legacy blob");

            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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

            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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

            let cfg = test_cfg(&context, NZU64!(2));
            let mut journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 1);

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
            assert_eq!(journal.bounds().start, 2);

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
            assert_eq!(journal.test_oldest_blob(), Some(1));
            assert_eq!(journal.test_newest_blob(), Some(5));
            assert_eq!(journal.bounds().start, 2);

            // Prune first 3 blobs (6 items)
            journal
                .prune(3 * cfg.items_per_blob.get())
                .await
                .expect("failed to prune journal 2");
            assert_eq!(journal.test_oldest_blob(), Some(3));
            assert_eq!(journal.test_newest_blob(), Some(5));
            assert_eq!(journal.bounds().start, 6);

            // Try pruning (more than) everything in the journal.
            journal
                .prune(10000)
                .await
                .expect("failed to max-prune journal");
            let size = journal.size();
            assert_eq!(size, 10);
            assert_eq!(journal.test_oldest_blob(), Some(5));
            assert_eq!(journal.test_newest_blob(), Some(5));
            // Since the size of the journal is currently a multiple of items_per_blob, the newest blob
            // will be empty, and there will be no retained items.
            let bounds = journal.bounds();
            assert!(bounds.is_empty());
            // bounds.start should equal bounds.end when empty.
            assert_eq!(bounds.start, size);

            // Replaying from 0 should fail since all items before bounds.start are pruned
            {
                let reader = journal.snapshot().await.unwrap();
                let result = reader.replay(0, NZUsize!(1024)).await;
                assert!(matches!(result, Err(Error::ItemPruned(0))));
            }

            // Replaying from pruning_boundary should return empty stream
            {
                let reader = journal.snapshot().await.unwrap();
                let res = reader.replay(0, NZUsize!(1024)).await;
                assert!(matches!(res, Err(Error::ItemPruned(_))));

                let reader = journal.snapshot().await.unwrap();
                let stream = reader
                    .replay(journal.bounds().start, NZUsize!(1024))
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
            let mut journal = Journal::init(context.child("first"), cfg.clone())
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
            let mut journal = Journal::init(context.child("first"), cfg.clone())
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
                let reader = journal.snapshot().await.unwrap();
                let stream = reader
                    .replay(0, NZUsize!(1024))
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

            // Truncate a middle blob to a whole-item prefix (external corruption). Recovery
            // verifies blob lengths and rejects the short interior blob.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &40u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.resize(size - Digest::SIZE as u64)
                .await
                .expect("Failed to corrupt blob");
            blob.sync().await.expect("Failed to sync blob");

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_replay_stops_after_error() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
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
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let reader = journal.snapshot().await.unwrap();
            *context.storage_fault_config().write() = deterministic::FaultConfig {
                read_rate: Some(1.0),
                ..Default::default()
            };
            let stream = reader.replay(0, NZUsize!(1024)).await.unwrap();
            pin_mut!(stream);

            assert!(matches!(
                stream.next().await.unwrap(),
                Err(Error::Runtime(_))
            ));
            assert!(stream.next().await.is_none());

            *context.storage_fault_config().write() = deterministic::FaultConfig::default();
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_with_missing_historical_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0u64..5 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Delete a middle blob (external corruption): the retained blobs are no longer
            // contiguous, which is corruption.
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
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
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
                let reader = journal.snapshot().await.unwrap();
                let stream = reader
                    .replay(START_POS, NZUsize!(1024))
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
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..5 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Truncate the tail blob by 1 byte (external corruption): a partial trailing item
            // cannot arise from a crash, so init rejects it.
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

    /// A short non-newest blob cannot arise from a crash: every blob is fsynced before its
    /// successor is created. Verify init rejects it as corruption.
    #[test_traced]
    fn test_fixed_journal_short_interior_blob_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Fill 3 blobs (0..15), sync everything.
            for i in 0..15u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Shorten blob 1 to 4 whole items (external corruption).
            let (blob, _) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .expect("failed to open blob 1");
            blob.resize(4 * Digest::SIZE as u64).await.unwrap();
            blob.sync().await.unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_accepts_clean_short_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Set up via the public API: 5 items in blob 0 (full) + 2 items in blob 1
            // (partial), then sync and drop.
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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
            assert_eq!(journal.size(), 7);
            // Blobs 0 and 1 exist and we can read every position.
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

            // Set up via the public API: 5 items in blob 0 (full); rolling over implicitly
            // creates an empty blob 1 as the tail. Sync and drop.
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..5 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen: blob 0 is full, blob 1 is the empty tail. Size = 5, no repair.
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.size(), 5);
            for i in 0..5u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            assert_eq!(journal.test_newest_blob(), Some(1));
            journal.destroy().await.unwrap();
        });
    }

    /// A blob id past a gap cannot arise from a crash: blobs are created in order and only
    /// removed from the ends. Verify init rejects the gap as corruption.
    #[test_traced]
    fn test_fixed_journal_recover_sparse_blob_ids_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(1));
            let blob_partition = blob_partition(&cfg);

            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            journal.append(&test_digest(0)).await.unwrap();
            journal.sync().await.unwrap();
            drop(journal);

            // Add a far-future blob directly.
            let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
            let (blob, blob_size) = context
                .open(&blob_partition, &u64::MAX.to_be_bytes())
                .await
                .unwrap();
            let mut append = Writer::new(blob, blob_size, 2048, cache_ref).await.unwrap();
            let extra = test_digest(999);
            append.append(extra.as_ref()).await.unwrap();
            append.sync().await.unwrap();
            drop(append);

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A short oldest blob (behind a full newer blob) cannot arise from a crash. Verify init
    /// rejects it as corruption, including with a mid-blob pruning boundary.
    #[test_traced]
    fn test_fixed_journal_short_oldest_blob_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
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
            assert_eq!(journal.bounds(), 7..15);
            drop(journal);

            // Shorten the oldest blob by one whole item (external corruption).
            let (blob, size) = context
                .open(&blob_partition(&cfg), &1u64.to_be_bytes())
                .await
                .expect("failed to open oldest blob");
            blob.resize(size - Digest::SIZE as u64)
                .await
                .expect("failed to corrupt blob");
            blob.sync().await.expect("failed to sync blob");

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A mid-blob boundary hint referencing a removed blob is not a reachable crash state:
    /// prune stages its blob removals and boundary record in one batch. Verify it is rejected
    /// as corruption.
    #[test_traced]
    fn test_fixed_journal_stale_boundary_hint_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
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
            assert_eq!(journal.bounds(), 7..17);
            drop(journal);

            // Remove the boundary hint's blob, planting a mid-blob hint (7) that references
            // a blob behind the oldest retained one.
            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .expect("failed to remove stale oldest blob");

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A boundary hint ahead of the oldest blob is not a reachable crash state: prune stages
    /// its blob removals and boundary record in one batch, and a clear removes every blob in
    /// the same batch as its record. Verify it is rejected as corruption.
    #[test_traced]
    fn test_fixed_journal_boundary_hint_ahead_of_blobs_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 3)
                    .await
                    .unwrap();

            // Append 12 items (positions 3..15) spanning blobs 0, 1, 2.
            for i in 0..12u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            assert_eq!(journal.bounds(), 3..15);

            // Set the boundary hint to 8 (blob 1), then remove blob 1's blob so blob 0 is the
            // oldest. The boundary hint now references a blob ahead of the oldest blob, which
            // is the corruption we're testing.
            journal.checkpoint.set_boundary_hint(8).await.unwrap();
            drop(journal);

            context
                .remove(&blob_partition(&cfg), Some(&1u64.to_be_bytes()))
                .await
                .unwrap();

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// A boundary hint with no blobs is the cleared state (a clear's batch removes every blob
    /// and records the target; the tail is recreated on reopen). Verify init recovers to the
    /// recorded boundary instead of reporting corruption.
    #[test_traced]
    fn test_fixed_journal_boundary_hint_with_no_blobs_recovers_cleared() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();

            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Remove all blobs but leave the checkpoint (with a boundary hint of 7) intact:
            // exactly the state a crashed clear-to-7 leaves behind.
            for name in scan_partition(&context, &blob_partition(&cfg)).await {
                context
                    .remove(&blob_partition(&cfg), Some(&name))
                    .await
                    .unwrap();
            }

            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("cleared state must recover");
            assert_eq!(journal.bounds(), 7..7);
            assert_eq!(journal.append(&test_digest(7)).await.unwrap(), 7);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_prune_to_blob_boundary_removes_pruning_metadata() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
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
            assert_eq!(journal.bounds(), 7..15);

            journal.prune(10).await.expect("failed to prune journal");
            journal.sync().await.expect("failed to sync pruned journal");
            assert_eq!(journal.bounds(), 10..15);
            drop(journal);

            let checkpoint = Checkpoint::open(context.child("metadata"), &cfg.partition)
                .await
                .expect("failed to reopen checkpoint");
            assert!(checkpoint.boundary_hint().is_none());
            drop(checkpoint);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to reopen journal");
            assert_eq!(journal.bounds(), 10..15);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(3));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_recover_rejects_overlong_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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

            // Inject an extra item into blob 0 at the blob level so its length exceeds
            // items_per_blob -- this is what `recover_bounds` validates and rejects as Corruption.
            {
                let extra = test_digest(99);
                let cache_ref = CacheRef::from_pooler(&context, PAGE_SIZE, PAGE_CACHE_SIZE);
                let (blob, blob_size) = context
                    .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                    .await
                    .expect("failed to open blob 0");
                let mut append = Writer::new(blob, blob_size, 2048, cache_ref)
                    .await
                    .expect("failed to wrap blob 0");
                append
                    .append(extra.as_ref())
                    .await
                    .expect("failed to append extra item");
                append.sync().await.expect("failed to sync corrupted blob");
            }

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    /// Unsynced appends vanish atomically on crash: the blob reads back exactly its last-synced
    /// state, so no torn or zero-filled tail can survive for recovery to repair.
    #[test_traced("DEBUG")]
    fn test_fixed_journal_recover_from_unwritten_data() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Sync a single item, then append more without syncing and crash.
            journal
                .append(&test_digest(0))
                .await
                .expect("failed to append data");
            journal.sync().await.expect("Failed to sync journal");
            for i in 1..4u64 {
                journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
            }
            assert_eq!(journal.size(), 4);
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("Failed to re-initialize journal");

            // Only the synced item survives. The unsynced suffix vanished with the crash.
            assert_eq!(journal.size(), 1);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(0));

            // Make sure journal still works for appending.
            journal
                .append(&test_digest(1))
                .await
                .expect("failed to append data");

            journal.destroy().await.unwrap();
        });
    }

    /// A blob extended with junk that is not a whole number of items is corruption, not a
    /// repairable torn write.
    #[test_traced]
    fn test_fixed_journal_partial_item_extension_is_corruption() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            journal
                .append(&test_digest(0))
                .await
                .expect("failed to append data");
            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Extend the blob by a non-item-multiple of durable junk bytes.
            let (blob, size) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .expect("Failed to open blob");
            blob.write_at_sync(size, vec![0u8; 7])
                .await
                .expect("Failed to extend blob");

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewinding() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize the journal, allowing a max of 2 items per blob.
            let cfg = test_cfg(&context, NZU64!(2));
            let mut journal = Journal::init(context.child("first"), cfg.clone())
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
            assert_eq!(journal.size(), 1);
            assert!(matches!(journal.rewind(1).await, Ok(()))); // should be no-op
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size(), 0);

            // append 7 items
            for i in 0..7 {
                let pos = journal
                    .append(&test_digest(i))
                    .await
                    .expect("failed to append data");
                assert_eq!(pos, i);
            }
            assert_eq!(journal.size(), 7);

            // rewind back to item #4, which should prune 2 blobs
            assert!(matches!(journal.rewind(4).await, Ok(())));
            assert_eq!(journal.size(), 4);

            // rewind back to empty and ensure all blobs are rewound over
            assert!(matches!(journal.rewind(0).await, Ok(())));
            assert_eq!(journal.size(), 0);

            // stress test: add 100 items, rewind 49, repeat x10.
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(&test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size() - 49).await.unwrap();
            }
            const ITEMS_REMAINING: u64 = 10 * (100 - 49);
            assert_eq!(journal.size(), ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Repeat with a different blob size (3 items per blob)
            let mut cfg = test_cfg(&context, NZU64!(3));
            cfg.partition = "test-partition-2".into();
            let mut journal = Journal::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to initialize journal");
            for _ in 0..10 {
                for i in 0..100 {
                    journal
                        .append(&test_digest(i))
                        .await
                        .expect("failed to append data");
                }
                journal.rewind(journal.size() - 49).await.unwrap();
            }
            assert_eq!(journal.size(), ITEMS_REMAINING);

            journal.sync().await.expect("Failed to sync journal");
            drop(journal);

            // Make sure re-opened journal is as expected
            let mut journal: Journal<_, Digest> =
                Journal::init(context.child("third"), cfg.clone())
                    .await
                    .expect("failed to re-initialize journal");
            assert_eq!(journal.size(), 10 * (100 - 49));

            // Make sure rewinding works after pruning
            journal.prune(300).await.expect("pruning failed");
            assert_eq!(journal.size(), ITEMS_REMAINING);
            // Rewinding prior to our prune point should fail.
            assert!(matches!(
                journal.rewind(299).await,
                Err(Error::ItemPruned(299))
            ));
            // Rewinding to the prune point should work.
            // always remain in the journal.
            assert!(matches!(journal.rewind(300).await, Ok(())));
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 300);
            assert!(bounds.is_empty());

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewind_sync_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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
            journal.sync().await.expect("failed to sync journal");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.bounds(), 0..7);
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

    /// A crash after rewind but before sync recovers an intermediate state: blobs above the
    /// rewind target were durably removed, but the target blob's truncation was not yet synced.
    /// The recovered size lands between the rewind target and the pre-rewind size.
    #[test_traced]
    fn test_fixed_journal_rewind_crash_before_sync() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            // Blob 2 (positions 10, 11) was durably removed. Blob 1's truncation to 7 was not
            // synced, so its pre-rewind content survives.
            assert_eq!(journal.bounds(), 0..10);
            for i in 0..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_rewind_append_sync_reopen() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
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
            journal.sync().await.expect("failed to sync journal");
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");
            assert_eq!(journal.bounds(), 0..10);
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

    /// Filling a blob makes it durable at rollover (before the next blob is created), so a
    /// crash loses only the unsynced partial tail, never a filled blob.
    #[test_traced]
    fn test_fixed_recovery_rollover_makes_filled_blobs_durable() {
        let executor = deterministic::Runner::default();
        let (_, checkpoint) = executor.start_and_recover(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            // Fill blobs 0 and 1 (positions 0..4) and stage one unsynced item in blob 2,
            // then crash without ever calling sync.
            for i in 0..5u64 {
                assert_eq!(journal.append(&test_digest(i)).await.unwrap(), i);
            }
        });

        deterministic::Runner::from(checkpoint).start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let mut journal = Journal::<_, Digest>::init(context.child("recovered"), cfg.clone())
                .await
                .unwrap();
            // The filled blobs survived (synced at rollover). The partial tail item vanished.
            assert_eq!(journal.bounds(), 0..4);
            for i in 0..4u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            assert_eq!(journal.append(&test_digest(42)).await.unwrap(), 4);
            assert_eq!(journal.read(4).await.unwrap(), test_digest(42));
            journal.destroy().await.unwrap();
        });
    }

    /// Test that a crash partway through a multi-blob sync leaves a contiguous durable prefix
    /// that recovery preserves.
    ///
    /// `flush_dirty_blobs` syncs dirty blobs, and mutators take `&mut self` so no concurrent
    /// sync can interleave. This reproduces a crash after blobs 0 and 1 were synced but before
    /// blob 2, then asserts recovery keeps exactly the contiguous prefix 0..20.
    #[test_traced]
    fn test_fixed_recovery_partial_sync_loop_keeps_contiguous_prefix() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Fill blobs 0 and 1 and partially fill blob 2 (positions 20..25). Nothing is
            // synced yet, so only the created blobs are durable, all still empty.
            for i in 0..25u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            // Sync blobs 0 and 1 but not blob 2, simulating a crash after part of a
            // multi-blob sync became durable.
            {
                journal.test_sync_blob(0).await.unwrap();
                journal.test_sync_blob(1).await.unwrap();
            }
            drop(journal);

            // The durable data is exactly the contiguous prefix: blobs 0 and 1 hold items and
            // blob 2 is an empty trailing blob.
            let names = scan_partition(&context, &blob_partition(&cfg)).await;
            assert_eq!(names.len(), 3);
            for (blob, name) in names.iter().enumerate() {
                let (_blob, size) = context.open(&blob_partition(&cfg), name).await.unwrap();
                if blob < 2 {
                    assert!(size > 0, "blob {blob} should be durable");
                } else {
                    assert_eq!(size, 0, "blob {blob} should be empty");
                }
            }

            // Recovery preserves exactly the contiguous prefix 0..20.
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 0..20);
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

    /// A crash right after pruning must not lose retained items that were appended but never
    /// synced. Blob removal is durable, so prune flushes every dirty blob first: otherwise the
    /// unsynced tail would vanish with the crash and recovery would truncate the journal to
    /// empty even though the removal survived.
    #[test_traced]
    fn test_fixed_recovery_prune_crash_retains_unsynced_tail() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            // Durably persist blob 0 (positions 0..10), then append positions 10..25 across
            // blobs 1 and 2 without syncing.
            for i in 0..10u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            for i in 10..25u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            // Prune away blob 0, then crash before any sync.
            assert!(journal.prune(10).await.unwrap());
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            assert_eq!(journal.bounds(), 10..25);
            for i in 10..25u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }
            journal.destroy().await.unwrap();
        });
    }

    /// Test recovery when the oldest blob is empty but a newer blob still holds durable items.
    ///
    /// A contiguous journal can only populate a later blob after durably filling the earlier
    /// one, so an empty oldest blob with a populated newer blob cannot arise from a crash and
    /// is rejected as corruption.
    #[test_traced]
    fn test_fixed_recovery_empty_oldest_blob_orphaned_newer_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));

            // Durably persist blobs 0 and 1 (positions 0..20).
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..20u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Empty the oldest blob (external corruption).
            let (blob0, size0) = context
                .open(&blob_partition(&cfg), &0u64.to_be_bytes())
                .await
                .unwrap();
            assert!(size0 > 0);
            blob0.resize(0).await.unwrap();
            blob0.sync().await.unwrap();

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
            let mut journal = Journal::init(context.child("first"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Verify empty state
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 0);
            assert!(bounds.is_empty());

            // Append 1 item
            let pos = journal
                .append(&test_digest(0))
                .await
                .expect("failed to append");
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);

            // Sync
            journal.sync().await.expect("failed to sync");

            // Read from size() - 1
            let value = journal
                .read(journal.size() - 1)
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
                assert_eq!(journal.size(), i + 1);

                // Verify we can read the just-appended item at size() - 1
                let value = journal
                    .read(journal.size() - 1)
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
            assert_eq!(journal.size(), 10);

            // bounds.start should be 5
            assert_eq!(journal.bounds().start, 5);

            // Reading from size() - 1 (position 9) should still work
            let value = journal
                .read(journal.size() - 1)
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
                    .read(journal.size() - 1)
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
            assert_eq!(journal.size(), 15);

            // Verify bounds.start is preserved
            assert_eq!(journal.bounds().start, 5);

            // Reading from size() - 1 should work after restart
            let value = journal
                .read(journal.size() - 1)
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
            let mut journal = Journal::init(context.child("third"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 10 items (positions 0-9)
            for i in 0..10u64 {
                journal.append(&test_digest(i + 100)).await.unwrap();
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
            let journal = Journal::<_, Digest>::init(context.child("fourth"), cfg.clone())
                .await
                .expect("failed to re-initialize journal");

            // Verify state after restart
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert_eq!(bounds.start, 5);

            // Reading from size() - 1 (position 9) should work
            let value = journal.read(journal.size() - 1).await.unwrap();
            assert_eq!(value, test_digest(109));

            // Verify all retained positions (5-9) work
            for i in 5..10u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i + 100));
            }

            journal.destroy().await.expect("failed to destroy journal");

            // === Test 6: Prune all items (edge case) ===
            let mut journal = Journal::init(context.child("storage"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            for i in 0..5u64 {
                journal.append(&test_digest(i + 200)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Prune all items
            journal.prune(5).await.unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 5); // Size unchanged
            assert!(bounds.is_empty()); // All pruned

            // size() - 1 = 4, but position 4 is pruned
            let result = journal.read(journal.size() - 1).await;
            assert!(matches!(result, Err(Error::ItemPruned(4))));

            // After appending, reading works again
            journal.append(&test_digest(205)).await.unwrap();
            assert_eq!(journal.bounds().start, 5);
            assert_eq!(
                journal.read(journal.size() - 1).await.unwrap(),
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
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 0)
                    .await
                    .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 0);
            assert!(bounds.is_empty());

            // Next append should get position 0
            let pos = journal.append(&test_digest(100)).await.unwrap();
            assert_eq!(pos, 0);
            assert_eq!(journal.size(), 1);
            assert_eq!(journal.read(0).await.unwrap(), test_digest(100));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_max_size_rejected() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(1));
            cfg.partition = "max-size-rejected".into();

            // A journal sized at `u64::MAX` could never accept an append, so init rejects it.
            assert!(matches!(
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg, u64::MAX).await,
                Err(Error::SizeOverflow)
            ));
        });
    }

    #[test_traced]
    fn test_fixed_journal_append_size_overflow() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(1));
            cfg.partition = "append-size-overflow".into();

            // Initialize one item shy of the maximum size.
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("near_max"), cfg, u64::MAX - 1)
                    .await
                    .unwrap();

            // The first append fills the last representable position.
            assert_eq!(journal.append(&test_digest(7)).await.unwrap(), u64::MAX - 1);
            assert_eq!(journal.size(), u64::MAX);

            // The next append would overflow the size; it must return a recoverable error
            // rather than panicking.
            assert!(matches!(
                journal.append(&test_digest(8)).await,
                Err(Error::SizeOverflow)
            ));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_near_max_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(10));
            cfg.partition = "replay-near-max-size".into();

            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("near_max"), cfg, u64::MAX - 1)
                    .await
                    .unwrap();
            let expected = test_digest(7);
            assert_eq!(journal.append(&expected).await.unwrap(), u64::MAX - 1);

            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader.replay(u64::MAX - 1, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let (pos, item) = stream.next().await.unwrap().unwrap();
                assert_eq!(pos, u64::MAX - 1);
                assert_eq!(item, expected);
                assert!(stream.next().await.is_none());
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_blob_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 10 (exactly at blob 2 boundary with items_per_blob=5)
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 10)
                    .await
                    .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 10);
            assert!(bounds.is_empty());

            // Next append should get position 10
            let pos = journal.append(&test_digest(1000)).await.unwrap();
            assert_eq!(pos, 10);
            assert_eq!(journal.size(), 11);
            assert_eq!(journal.read(10).await.unwrap(), test_digest(1000));

            // Can continue appending
            let pos = journal.append(&test_digest(1001)).await.unwrap();
            assert_eq!(pos, 11);
            assert_eq!(journal.read(11).await.unwrap(), test_digest(1001));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_mid_blob() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 7 (middle of blob 1 with items_per_blob=5)
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 7)
                    .await
                    .unwrap();

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 7);
            // No data exists yet after init_at_size
            assert!(bounds.is_empty());

            // Reading before bounds.start should return ItemPruned
            assert!(matches!(journal.read(5).await, Err(Error::ItemPruned(5))));
            assert!(matches!(journal.read(6).await, Err(Error::ItemPruned(6))));

            // Next append should get position 7
            let pos = journal.append(&test_digest(700)).await.unwrap();
            assert_eq!(pos, 7);
            assert_eq!(journal.size(), 8);
            assert_eq!(journal.read(7).await.unwrap(), test_digest(700));
            // Now bounds.start should be 7 (first data position)
            assert_eq!(journal.bounds().start, 7);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_append_many_after_mid_blob_start() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(100));
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 150)
                    .await
                    .unwrap();

            let items: Vec<_> = (0..100u64).map(|i| test_digest(1500 + i)).collect();
            let last = journal.append_many(Many::Flat(&items)).await.unwrap();
            assert_eq!(last, 249);
            assert_eq!(journal.bounds(), 150..250);

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
            assert_eq!(journal.bounds(), 150..250);
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
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 15)
                    .await
                    .unwrap();

            // Append some items
            for i in 0..5u64 {
                let pos = journal.append(&test_digest(1500 + i)).await.unwrap();
                assert_eq!(pos, 15 + i);
            }

            assert_eq!(journal.size(), 20);

            // Sync and reopen
            journal.sync().await.unwrap();
            drop(journal);

            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            // Size and data should be preserved
            let bounds = journal.bounds();
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

            let bounds = journal.bounds();
            assert_eq!(bounds.end, 15);
            assert!(bounds.is_empty());

            // Drop without writing any data
            drop(journal);

            // Reopen and verify size persisted
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();

            let bounds = journal.bounds();
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
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 1000)
                    .await
                    .unwrap();

            let bounds = journal.bounds();
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
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 20)
                    .await
                    .unwrap();

            // Append items 20-29
            for i in 0..10u64 {
                journal.append(&test_digest(2000 + i)).await.unwrap();
            }

            assert_eq!(journal.size(), 30);

            // Prune to position 25
            journal.prune(25).await.unwrap();

            let bounds = journal.bounds();
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
            let mut journal = Journal::init(context.child("journal"), cfg.clone())
                .await
                .expect("failed to initialize journal");

            // Append 25 items (positions 0-24, spanning 3 blobs)
            for i in 0..25u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 25);
            journal.sync().await.unwrap();

            // Clear to position 100, effectively resetting the journal
            journal.clear_to_size(100).await.unwrap();
            assert_eq!(journal.size(), 100);

            // Old positions should fail
            for i in 0..25 {
                assert!(matches!(journal.read(i).await, Err(Error::ItemPruned(_))));
            }

            // Verify size persists after restart without writing any data
            drop(journal);
            let mut journal =
                Journal::<_, Digest>::init(context.child("journal_after_clear"), cfg.clone())
                    .await
                    .expect("failed to re-initialize journal after clear");
            assert_eq!(journal.size(), 100);

            // Append new data starting at position 100
            for i in 100..105u64 {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, i);
            }
            assert_eq!(journal.size(), 105);

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

            assert_eq!(journal.size(), 105);
            for i in 100..105u64 {
                assert_eq!(journal.read(i).await.unwrap(), test_digest(i));
            }

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size_rejects_max() {
        // `clear_to_size` must reject `u64::MAX` like `init_at_size`: such a journal could never
        // accept an append.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg)
                .await
                .unwrap();
            assert!(matches!(
                journal.clear_to_size(u64::MAX).await,
                Err(Error::SizeOverflow)
            ));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_sync_crash_meta_none_boundary_aligned() {
        // Old meta = None (aligned), new boundary = aligned.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();

            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.start, 0);
            assert_eq!(bounds.end, 5);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_missing_metadata_with_short_blob_is_corruption() {
        // Clearing all metadata loses the mid-blob boundary hint. Recovery falls back to the
        // blob boundary and finds a short non-tail blob, which is corruption.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // Simulate metadata deletion (corruption).
            journal.checkpoint.clear().await.unwrap();
            drop(journal);

            let result = Journal::<_, Digest>::init(context.child("second"), cfg.clone()).await;
            assert!(matches!(result, Err(Error::Corruption(_))));
        });
    }

    #[test_traced]
    fn test_fixed_journal_sync_crash_meta_mid_boundary_unchanged() {
        // Old meta = Some(mid), new boundary = mid-blob (same value).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .unwrap();
            let bounds = journal.bounds();
            assert_eq!(bounds.start, 7);
            assert_eq!(bounds.end, 10);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_prune_does_not_move_boundary_backwards() {
        // Pruning to a position earlier than pruning_boundary (within the same blob)
        // should not move the boundary backwards.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            // init_at_size(7) sets pruning_boundary = 7 (mid-blob in blob 1)
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            // Append 5 items at positions 7-11, filling blob 1 and part of blob 2
            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            // Prune to position 5 (blob 1 start) should NOT move boundary back from 7 to 5
            journal.prune(5).await.unwrap();
            assert_eq!(journal.bounds().start, 7);
            journal.destroy().await.unwrap();
        });
    }

    /// Prune flushes every dirty blob and clears the dirty state, so a sync issued right
    /// after must not attempt to sync the removed blobs.
    #[test_traced]
    fn test_fixed_journal_sync_after_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("journal"), cfg.clone())
                .await
                .unwrap();

            for i in 0..12 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            journal.prune(5).await.unwrap();
            journal
                .sync()
                .await
                .expect("sync should not try to sync pruned blobs");
            assert_eq!(journal.bounds(), 5..12);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_replay_after_init_at_size_spanning_blobs() {
        // Test replay when first blob begins mid-blob: init_at_size creates a journal
        // where pruning_boundary is mid-blob, then we append across multiple blobs.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Initialize at position 7 (mid-blob with items_per_blob=5)
            // Blob 1 (positions 5-9) begins mid-blob: only positions 7, 8, 9 have data
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 7)
                    .await
                    .unwrap();

            // Append 13 items (positions 7-19), spanning blobs 1, 2, 3
            for i in 0..13u64 {
                let pos = journal.append(&test_digest(100 + i)).await.unwrap();
                assert_eq!(pos, 7 + i);
            }
            assert_eq!(journal.size(), 20);
            journal.sync().await.unwrap();

            // Replay from pruning_boundary
            {
                let reader = journal.snapshot().await.unwrap();
                let stream = reader
                    .replay(7, NZUsize!(1024))
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
                let reader = journal.snapshot().await.unwrap();
                let stream = reader
                    .replay(12, NZUsize!(1024))
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

            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("storage"), cfg.clone(), 10)
                    .await
                    .unwrap();

            // Append a few items (positions 10, 11, 12)
            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 13);

            // Rewind to position 11 should work
            journal.rewind(11).await.unwrap();
            assert_eq!(journal.size(), 11);

            // Rewind to position 10 (pruning_boundary) should work
            journal.rewind(10).await.unwrap();
            assert_eq!(journal.size(), 10);

            // Rewind to before pruning_boundary should fail
            let result = journal.rewind(9).await;
            assert!(matches!(result, Err(Error::ItemPruned(9))));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_crash_scenarios() {
        // A reset's batch removes every blob and records the target boundary atomically; the
        // only crash window is BEFORE the new tail blob is recreated on reopen (a boundary
        // hint with no blobs, or with only the empty tail).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));

            // Setup: Create a journal with some data and mid-blob metadata
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 7)
                    .await
                    .unwrap();
            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Crash Scenario 1: the reset batch landed (blobs removed + boundary recorded) but
            // the new tail blob was never created.
            let blob_part = blob_partition(&cfg);
            let mut checkpoint = Checkpoint::open(context.child("intent_meta"), &cfg.partition)
                .await
                .unwrap();
            checkpoint.set_boundary_hint(12).await.unwrap();
            drop(checkpoint);
            context.remove(&blob_part, None).await.unwrap();

            // Recovery adopts the recorded boundary and recreates the tail.
            let journal = Journal::<_, Digest>::init(
                context.child("crash").with_attribute("index", 1),
                cfg.clone(),
            )
            .await
            .expect("init failed after clear crash");
            let bounds = journal.bounds();
            assert_eq!(bounds.end, 12);
            assert_eq!(bounds.start, 12);
            journal.destroy().await.unwrap();

            // Crash Scenario 2: the reset batch landed and the new (empty) tail blob was
            // created, but nothing was appended before the crash.
            let mut checkpoint = Checkpoint::open(context.child("restore_meta"), &cfg.partition)
                .await
                .unwrap();
            checkpoint.set_boundary_hint(2).await.unwrap();
            drop(checkpoint);
            let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap(); // Ensure it exists
            drop(blob);

            let journal = Journal::<_, Digest>::init(
                context.child("crash").with_attribute("index", 2),
                cfg.clone(),
            )
            .await
            .expect("init failed after create crash");

            let bounds = journal.bounds();
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

            // Setup: Init at 12 (Blob 2, offset 2)
            // Metadata = 12
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 12)
                    .await
                    .unwrap();
            journal.sync().await.unwrap();
            drop(journal);

            // Crash Scenario: clear_to_size(2)'s batch landed (blobs removed + boundary
            // recorded) and the new tail blob was created, but the process crashed before
            // using the journal.

            let blob_part = blob_partition(&cfg);
            let mut checkpoint = Checkpoint::open(context.child("meta"), &cfg.partition)
                .await
                .unwrap();
            checkpoint.set_boundary_hint(2).await.unwrap();
            drop(checkpoint);

            context.remove(&blob_part, None).await.unwrap();

            let (blob, _) = context.open(&blob_part, &0u64.to_be_bytes()).await.unwrap();
            blob.sync().await.unwrap();

            let journal = Journal::<_, Digest>::init(context.child("crash_clear"), cfg.clone())
                .await
                .expect("init failed after clear_to_size crash");

            let bounds = journal.bounds();
            assert_eq!(bounds.start, 2);
            assert_eq!(bounds.end, 2);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_init_at_size_discards_stale_corrupt_blobs() {
        // The reset removes blob partitions wholesale (no name parsing), so blobs whose names
        // would fail `Partition::open_all` cannot block a reset.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let blob_part = blob_partition(&cfg);
            let (blob, _) = context.open(&blob_part, b"not-u64").await.unwrap();
            blob.write_at_sync(0, vec![1, 2, 3]).await.unwrap();
            drop(blob);

            let journal =
                Journal::<_, Digest>::init_at_size(context.child("recover"), cfg.clone(), 12)
                    .await
                    .expect("reset should discard stale corrupt blobs before blob parsing");
            assert_eq!(journal.bounds(), 12..12);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_clear_to_size_mid_blob_reopens() {
        // A mid-blob clear target recovers exactly across reopens: the boundary hint is
        // trusted while it belongs to the (recreated) oldest blob.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal =
                Journal::<_, Digest>::init_at_size(context.child("first"), cfg.clone(), 10)
                    .await
                    .unwrap();

            for i in 0..6u64 {
                let pos = journal.append(&test_digest(i)).await.unwrap();
                assert_eq!(pos, 10 + i);
            }
            journal.sync().await.unwrap();
            journal.clear_to_size(15).await.unwrap();
            assert_eq!(journal.bounds(), 15..15);
            drop(journal);

            let journal = Journal::<_, Digest>::init(context.child("second"), cfg.clone())
                .await
                .expect("init failed after mid-blob clear");
            assert_eq!(journal.bounds(), 15..15);
            drop(journal);

            let mut journal = Journal::<_, Digest>::init(context.child("third"), cfg.clone())
                .await
                .expect("init failed after reopening mid-blob clear");
            assert_eq!(journal.bounds(), 15..15);
            assert!(matches!(journal.read(14).await, Err(Error::ItemPruned(14))));
            let pos = journal.append(&test_digest(100)).await.unwrap();
            assert_eq!(pos, 15);
            assert_eq!(journal.read(15).await.unwrap(), test_digest(100));
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
                .await
                .unwrap();

            let items = journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[])
                .await
                .unwrap();
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
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 5);

            let items = journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[0, 2, 4])
                .await
                .unwrap();
            assert_eq!(items, vec![test_digest(0), test_digest(2), test_digest(4)]);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    #[should_panic(expected = "positions must be strictly increasing")]
    fn test_read_many_rejects_unsorted_positions() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();
            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            let _ = journal.snapshot().await.unwrap().read_many(&[2, 1]).await;
        });
    }

    #[test_traced]
    #[should_panic(expected = "positions must be strictly increasing")]
    fn test_read_many_rejects_duplicate_positions() {
        // Duplicates are not strictly increasing either.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();
            for i in 0..5u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            let _ = journal.snapshot().await.unwrap().read_many(&[1, 1]).await;
        });
    }

    #[test_traced]
    fn test_read_many_across_blobs() {
        // Positions spanning multiple blobs (items_per_blob=3).
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(3));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..9u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 9);
            // Blobs: [0,1,2], [3,4,5], [6,7,8]

            let items = journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[1, 4, 7])
                .await
                .unwrap();
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
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..9u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 9);
            journal.sync().await.unwrap();

            // Prune first blob [0,1,2].
            journal.prune(3).await.unwrap();
            assert_eq!(journal.bounds(), 3..9);

            let items = journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[3, 5, 8])
                .await
                .unwrap();
            assert_eq!(items, vec![test_digest(3), test_digest(5), test_digest(8)]);

            // Pruned position should error.
            let err = journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[1])
                .await
                .unwrap_err();
            assert!(matches!(err, Error::ItemPruned(1)));

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_out_of_range() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(10));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..3u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 3);

            let err = journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[0, 5])
                .await
                .unwrap_err();
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
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..20u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(journal.size(), 20);
            journal.sync().await.unwrap();

            let positions: Vec<u64> = (0..20).collect();
            let reader = journal.snapshot().await.unwrap();
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
    fn test_try_read_many_sync_matches_read_many() {
        // Cached positions are served synchronously and match the async batched read.
        // Positions that fail validation are misses rather than errors.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(4));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..20u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let positions: Vec<u64> = (0..20).collect();
            let reader = journal.snapshot().await.unwrap();
            let expected = reader.read_many(&positions).await.unwrap();

            // Every synchronously served item must match the async read. Positions the
            // 3-page test cache cannot hold are misses, never wrong values.
            let served = reader.try_read_many_sync(&positions);
            assert_eq!(served.len(), positions.len());
            for (item, expected) in served.iter().zip(&expected) {
                if let Some(item) = item {
                    assert_eq!(item, expected);
                }
            }

            // The last blob (positions 16..20) spans at most the cache capacity, so after
            // warming exactly those positions they are all served synchronously.
            let tail: Vec<u64> = (16..20).collect();
            reader.read_many(&tail).await.unwrap();
            let served = reader.try_read_many_sync(&tail);
            for (item, pos) in served.iter().zip(&tail) {
                assert_eq!(
                    item.as_ref().expect("warmed position is served"),
                    &expected[*pos as usize]
                );
            }

            // A long-evicted position is a miss.
            assert!(reader.try_read_many_sync(&[0])[0].is_none());

            // An out-of-range position is a miss, not an error, and does not poison the
            // valid position grouped before it.
            let served = reader.try_read_many_sync(&[19, 20]);
            assert!(served[0].is_some());
            assert!(served[1].is_none());
            drop(served);
            drop(reader);

            // After a rewind the journal's end is not blob-aligned, so an out-of-range
            // position can share a blob with a valid one. Validation trims the batch
            // instead of poisoning the shared group.
            journal.rewind(18).await.unwrap();
            let reader = journal.snapshot().await.unwrap();
            reader.read_many(&[17]).await.unwrap();
            let served = reader.try_read_many_sync(&[17, 18]);
            assert!(served[0].is_some());
            assert!(served[1].is_none());
            drop(served);
            drop(reader);

            // A pruned position is trimmed from the prefix rather than reaching offset
            // derivation, and the valid remainder is still served.
            journal.prune(8).await.unwrap();
            let reader = journal.snapshot().await.unwrap();
            reader.read_many(&[9]).await.unwrap();
            let served = reader.try_read_many_sync(&[3, 9]);
            assert!(served[0].is_none());
            assert!(served[1].is_some());
            drop(served);
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_probe_then_read_many_matches_read_many() {
        // A probe completed by one batched read over its declined positions returns the same
        // items as read_many, cold and warm.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(4));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..20u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let positions: Vec<u64> = (0..20).collect();
            let reader = journal.snapshot().await.unwrap();
            let expected: Vec<_> = (0..20).map(test_digest).collect();
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
    fn test_fixed_journal_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(2));
            let mut journal =
                Journal::<_, Digest>::init(context.child("fixed_metrics"), cfg.clone())
                    .await
                    .unwrap();

            let items: Vec<_> = (0..5).map(test_digest).collect();
            journal.append_many(Many::Flat(&items)).await.unwrap();
            journal.append(&test_digest(5)).await.unwrap();
            journal.sync().await.unwrap();
            journal.snapshot().await.unwrap().read(0).await.unwrap();
            journal.snapshot().await.unwrap().try_read_sync(0).unwrap();
            journal
                .snapshot()
                .await
                .unwrap()
                .read_many(&[1, 2, 4])
                .await
                .unwrap();
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
                "fixed_metrics_items_read_total 5",
                "fixed_metrics_sync_calls_total 1",
                "fixed_metrics_append_duration_count 1",
                "fixed_metrics_append_many_duration_count 1",
                "fixed_metrics_read_duration_count 0",
                "fixed_metrics_read_many_duration_count 1",
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
    /// A snapshot's bounds and contents are frozen across appends and rolls.
    #[test_traced]
    fn test_snapshot_frozen_across_roll() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            let snapshot = journal.snapshot().await.unwrap();
            assert_eq!(snapshot.bounds(), 0..7);

            // Appending past the blob boundary rolls the snapshot's tail blob into
            // history; the snapshot keeps reading it through its own handle.
            for i in 7..23u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert_eq!(snapshot.bounds(), 0..7);
            for i in 0..7u64 {
                assert_eq!(snapshot.read(i).await.unwrap(), test_digest(i));
            }
            assert!(matches!(
                snapshot.read(7).await,
                Err(Error::ItemOutOfRange(7))
            ));

            let fresh = journal.snapshot().await.unwrap();
            assert_eq!(fresh.bounds(), 0..23);
            assert_eq!(fresh.read(22).await.unwrap(), test_digest(22));

            drop(snapshot);
            drop(fresh);
            journal.destroy().await.unwrap();
        });
    }

    /// A snapshot taken before a prune keeps reading the pruned range; later snapshots observe
    /// the new boundary.
    #[test_traced]
    fn test_prune_under_snapshot() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..17u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            let snapshot = journal.snapshot().await.unwrap();
            assert!(journal.prune(12).await.unwrap());

            // The straggler reads the pruned range through its own handles.
            assert_eq!(snapshot.bounds(), 0..17);
            for i in 0..17u64 {
                assert_eq!(snapshot.read(i).await.unwrap(), test_digest(i));
            }

            let fresh = journal.snapshot().await.unwrap();
            assert_eq!(fresh.bounds(), 10..17);
            assert!(matches!(fresh.read(3).await, Err(Error::ItemPruned(3))));

            drop(snapshot);
            drop(fresh);
            journal.destroy().await.unwrap();
        });
    }

    /// Every snapshot shipped to a concurrent task is fully readable while the writer keeps
    /// appending and rolling.
    #[test_traced]
    fn test_snapshots_readable_during_concurrent_appends() {
        let executor = deterministic::Runner::seeded(7);
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
                .await
                .unwrap();

            let (mut tx, mut rx) =
                futures::channel::mpsc::channel::<Reader<'static, Context, Digest>>(8);
            let validator = context.child("validator").spawn(|_| async move {
                let mut validated = 0usize;
                while let Some(snapshot) = rx.next().await {
                    let bounds = snapshot.bounds();
                    for i in bounds.clone() {
                        assert_eq!(snapshot.read(i).await.unwrap(), test_digest(i));
                    }
                    validated += (bounds.end - bounds.start) as usize;
                }
                validated
            });

            for i in 0..40u64 {
                journal.append(&test_digest(i)).await.unwrap();
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

    /// A snapshot taken before rolls and a prune replays its full frozen range, streaming its
    /// then-tail blob through the snapshot's own handle.
    #[test_traced]
    fn test_replay_from_stale_snapshot() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_cfg(&context, NZU64!(5));
            let mut journal = Journal::<_, Digest>::init(context.child("j"), cfg)
                .await
                .unwrap();
            for i in 0..7u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }

            // Positions 5..7 live in the snapshot's tail blob.
            let snapshot = journal.snapshot().await.unwrap();
            assert_eq!(snapshot.bounds(), 0..7);

            // Roll the snapshot's tail into history, then prune both of its blobs away.
            for i in 7..23u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            assert!(journal.prune(12).await.unwrap());

            {
                let stream = snapshot.replay(0, NZUsize!(1024)).await.unwrap();
                pin_mut!(stream);
                let mut expected = 0u64;
                while let Some(result) = stream.next().await {
                    let (pos, item) = result.unwrap();
                    assert_eq!(pos, expected);
                    assert_eq!(item, test_digest(pos));
                    expected += 1;
                }
                assert_eq!(expected, 7);
            }

            drop(snapshot);
            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_read_many_sparse_sections_and_hit_accounting() {
        // Verify the batched read path is byte-identical to per-item reads across multiple
        // blobs, with a mid-blob pruning boundary, a sparse subset of positions, and
        // exact hit/miss accounting over a mixed cached/uncached batch.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(8));
            // Keep the whole batch resident so hit accounting is stable. Otherwise, the batch may
            // evict a page that a later per-item probe still expects to hit.
            cfg.page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(16));
            let mut journal = Journal::init(context.child("j"), cfg).await.unwrap();

            for i in 0..50u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            // Prune mid-blob so first_in_blob differs from the blob start.
            journal.prune(11).await.unwrap();

            let reader = journal.snapshot().await.unwrap();

            // Sparse subset spanning multiple blobs, including the pruning boundary.
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
    fn test_read_many_cold_blob_groups() {
        // Read a batch whose positions are all cache misses spread over four blobs, so the whole
        // batch is served by per-blob group reads into disjoint slices of the shared output
        // buffer. Each digest encodes its position, so a group read into the wrong slice fails
        // the value assertions.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut cfg = test_cfg(&context, NZU64!(8));
            cfg.page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(32));
            let mut journal = Journal::<_, Digest>::init(context.child("first"), cfg.clone())
                .await
                .unwrap();
            for i in 0..40u64 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();
            drop(journal);

            // Reopen with a fresh page cache so every full page is cold. The positions avoid
            // each blob's trailing bytes, which sealed blobs keep in memory and always serve
            // synchronously.
            cfg.page_cache = CacheRef::from_pooler(&context, PAGE_SIZE, NZUsize!(32));
            let mut journal = Journal::<_, Digest>::init(context.child("second"), cfg)
                .await
                .unwrap();
            let reader = journal.snapshot().await.unwrap();
            let positions = [1, 5, 10, 14, 17, 22, 25, 30];
            for pos in positions {
                assert!(reader.try_read_sync(pos).is_none(), "position {pos}");
            }

            // Every item requires a blob read, split into four groups of two.
            let before = context.encode();
            let batch = reader.read_many(&positions).await.unwrap();
            let after = context.encode();
            assert_eq!(
                counter(&after, "second_cache_misses") - counter(&before, "second_cache_misses"),
                positions.len() as u64
            );
            assert_eq!(
                counter(&after, "second_cache_hits"),
                counter(&before, "second_cache_hits")
            );
            for (i, &pos) in positions.iter().enumerate() {
                assert_eq!(batch[i], test_digest(pos), "position {pos}");
            }

            // The first pass cached every page it faulted, so a second pass is all hits and must
            // return the same items.
            let before = context.encode();
            let batch = reader.read_many(&positions).await.unwrap();
            let after = context.encode();
            assert_eq!(
                counter(&after, "second_cache_hits") - counter(&before, "second_cache_hits"),
                positions.len() as u64
            );
            for (i, &pos) in positions.iter().enumerate() {
                assert_eq!(batch[i], test_digest(pos), "position {pos}");
            }
            drop(reader);

            journal.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_fixed_journal_read_miss_timed() {
        // Reads served from storage record a read_duration sample; cache hits do not.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let mut journal =
                Journal::<_, Digest>::init(context.child("miss"), test_cfg(&context, NZU64!(2)))
                    .await
                    .unwrap();
            for i in 0..20 {
                journal.append(&test_digest(i)).await.unwrap();
            }
            journal.sync().await.unwrap();

            // The page cache cannot hold every page, so some position must be cold.
            let reader = journal.snapshot().await.unwrap();
            let pos = (0..20)
                .find(|&pos| reader.try_read_sync(pos).is_none())
                .expect("some position should be cold");
            assert_eq!(reader.read(pos).await.unwrap(), test_digest(pos));
            drop(reader);

            let buffer = context.encode();
            assert!(buffer.contains("miss_read_duration_count 1"), "{buffer}");

            journal.destroy().await.unwrap();
        });
    }
}
