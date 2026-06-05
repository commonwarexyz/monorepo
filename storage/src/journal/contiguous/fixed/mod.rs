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
//! # Concurrency
//!
//! Mutators take `&mut self`; the journal is the only writer. Readers are owned snapshots
//! created by [`Journal::reader`]: bounds are frozen at creation, every in-bounds position stays
//! readable (including across a concurrent prune), and reads never block the writer.
//!
//! Three pieces of state are shared between the writer and readers:
//!
//! - `size` (atomic): the number of appended items. The writer stores it only after the bytes
//!   behind every position below it are readable, so a reader may read anything below the value
//!   it loads.
//! - The blob table (pointer to an immutable value): maps each retained blob to its read
//!   handle (a sealed blob or the live tail). Operations that add or drop blobs (roll,
//!   prune, rewind, clear) build a new table and swap the pointer; a published table is never
//!   modified, so a reader holding one always has valid handles. A version counter lets a
//!   reader confirm that a `(table, size)` pair is consistent.
//! - A count of live readers, which gates rewind's in-place truncation of sealed blobs.
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
//! - PRUNING_BOUNDARY_KEY: Stores the pruning boundary as a u64 when it's mid-blob (not a
//!   multiple of items_per_blob). Absent from legacy journals or when the boundary is
//!   blob-aligned, since it can be derived from the oldest blob.
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
//! Blobs are filled sequentially. Recovery walks the blob range from oldest to newest and
//! compares each blob's item count to its logical capacity:
//!
//! - A short or missing non-newest blob indicates a gap in durable data; recovery stops there
//!   and truncates newer blobs.
//! - The newest blob may be short, since it is the normal append frontier. Recovery includes
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
        contiguous::{
            metrics::FixedMetrics as Metrics,
            Many, Mutable,
        },
        Error,
    },
    metadata::Metadata,
    Context, Persistable,
};
use commonware_codec::CodecFixedShared;
use commonware_runtime::{
    buffer::paged::{Writer, CacheRef, Sealed},
    telemetry::metrics::GaugeExt as _,
    Blob,
};
use commonware_utils::{sequence::VecU64, sync::RwLock};
use futures::future::try_join_all;
use std::{
    future::Future,
    marker::PhantomData,
    num::{NonZeroU64, NonZeroUsize},
    sync::{
        atomic::{AtomicU64, AtomicUsize, Ordering},
        Arc,
    },
};
use tracing::warn;

mod io;
mod reader;
mod recovery;
mod state;
#[cfg(test)]
mod tests;

pub use reader::Reader;

use io::BlobIo;
pub(super) use recovery::CLEAR_TARGET_KEY;
use recovery::{PRUNING_BOUNDARY_KEY, RECOVERY_WATERMARK_KEY};
use state::{BlobTable, Shared};

/// Return the first retained logical position in `blob`.
#[inline]
pub(super) fn first_in_blob(pruning_boundary: u64, blob: u64, items_per_blob: u64) -> Result<u64, Error> {
    let start = blob
        .checked_mul(items_per_blob)
        .ok_or(Error::OffsetOverflow)?;
    Ok(pruning_boundary.max(start))
}

/// The writable tail blob.
pub(super) struct Tail<B: Blob> {
    pub(super) blob: u64,
    pub(super) writer: Writer<B>,
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

/// Implementation of `Journal` storage.
///
/// Historical blobs are immutable [`Sealed`] views; the journal owns the one writable tail.
/// Mutators take `&mut self`; readers operate on owned snapshots and never block the writer.
///
/// # Repair
///
/// Like
/// [sqlite](https://github.com/sqlite/sqlite/blob/8658a8df59f00ec8fcfea336a2a6a4b5ef79d2ee/src/wal.c#L1504-L1505)
/// and
/// [rocksdb](https://github.com/facebook/rocksdb/blob/0c533e61bc6d89fdf1295e8e0bcee4edb3aef401/include/rocksdb/options.h#L441-L445),
/// the first invalid data read will be considered the new end of the journal (and the
/// underlying blob will be truncated to the last valid item). Repair is performed during init.
pub struct Journal<E: Context, A> {
    io: BlobIo<E>,

    /// The writable tail: the blob containing the next append position.
    tail: Tail<E::Blob>,

    /// Stores the recovery watermark and, when the pruning boundary is mid-blob, the exact
    /// pruning boundary. Also stores an in-progress `CLEAR_TARGET_KEY` while a clear/reset is
    /// running.
    ///
    /// Metadata that advances the pruning boundary or recovery watermark is persisted only after
    /// the blob state it describes is durable. A lower recovery watermark is always safe to persist
    /// because it only expands the suffix external consumers may replay. Recovery rejects pruning
    /// metadata ahead of blob state and watermarks beyond the recovered size as corruption.
    metadata: Metadata<E, u64, VecU64>,

    /// Total items appended, including pruned. Published to readers via [`Shared::size`].
    size: u64,

    /// Items below this position are pruned. Published via the [`BlobTable`].
    pruning_boundary: u64,

    /// Earliest blob modified since the last `commit()` or `sync()`.
    dirty_from_blob: Option<u64>,

    shared: Arc<Shared<E::Blob>>,

    /// Maximum items per blob.
    items_per_blob: NonZeroU64,

    /// Shared with [Reader]s.
    metrics: Arc<Metrics<E>>,

    _phantom: PhantomData<A>,
}

impl<E: Context, A: CodecFixedShared> Journal<E, A> {
    /// Size of each entry in bytes.
    pub const CHUNK_SIZE: usize = A::SIZE;

    /// Size of each entry in bytes (as u64).
    pub const CHUNK_SIZE_U64: u64 = Self::CHUNK_SIZE as u64;

    /// Mark all blobs from `blob` onward as dirty.
    fn mark_dirty_from(&mut self, blob: u64) {
        self.dirty_from_blob = Some(
            self.dirty_from_blob
                .map_or(blob, |existing| existing.min(blob)),
        );
    }

    /// The writer's view of the current table.
    fn current_table(&self) -> Arc<BlobTable<E::Blob>> {
        self.shared.table.read().clone()
    }

    /// Construct a journal from recovered blobs, publishing the initial table.
    #[allow(clippy::too_many_arguments)]
    fn from_blobs(
        io: BlobIo<E>,
        sealed: Vec<Sealed<E::Blob>>,
        tail: Tail<E::Blob>,
        metadata: Metadata<E, u64, VecU64>,
        size: u64,
        pruning_boundary: u64,
        dirty_from_blob: Option<u64>,
        items_per_blob: NonZeroU64,
        metrics: Metrics<E>,
    ) -> Self {
        let _ = io.metrics.tracked.try_set(sealed.len() + 1);
        let table = BlobTable {
            version: 0,
            base_blob: tail.blob - sealed.len() as u64,
            sealed: sealed.into(),
            tail_reader: tail.writer.reader(),
            pruning_boundary,
        };
        let shared = Arc::new(Shared {
            size: AtomicU64::new(size),
            table: RwLock::new(Arc::new(table)),
            readers: AtomicUsize::new(0),
        });
        Self {
            io,
            tail,
            metadata,
            size,
            pruning_boundary,
            dirty_from_blob,
            shared,
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
        // scanning or opening blobs so corrupt stale blobs cannot block recovery of the reset.
        if let Some(clear_target) = metadata.get(&CLEAR_TARGET_KEY).copied().map(u64::from) {
            warn!(clear_target, "crash repair: completing interrupted clear");
            let new_partition = format!("{}-blobs", cfg.partition);
            Self::remove_blob_partition(&context, &cfg.partition).await?;
            Self::remove_blob_partition(&context, &new_partition).await?;
            let tail_blob = clear_target / items_per_blob;
            let io = BlobIo::new(
                context.child("blobs"),
                new_partition,
                cfg.page_cache,
                cfg.write_buffer,
            );
            let tail = Tail {
                blob: tail_blob,
                writer: io.open(tail_blob).await?,
            };
            Self::stage_pruning_boundary_metadata(&mut metadata, items_per_blob, clear_target);
            metadata.put(RECOVERY_WATERMARK_KEY, clear_target.into());
            metadata.remove(&CLEAR_TARGET_KEY);
            metadata.sync().await?;

            let metrics = Metrics::new(context);
            metrics.update(clear_target, clear_target, items_per_blob);
            return Ok(Self::from_blobs(
                io,
                Vec::new(),
                tail,
                metadata,
                clear_target,
                clear_target,
                None,
                cfg.items_per_blob,
                metrics,
            ));
        }

        let blob_partition = Self::select_blob_partition(&context, &cfg).await?;
        let io = BlobIo::new(
            context.child("blobs"),
            blob_partition,
            cfg.page_cache,
            cfg.write_buffer,
        );
        let mut pending = io.open_all().await?;

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
                io.remove_blob(newest).await?;
            }
            if let Some(writer) = pending.get(&repair.blob) {
                if repair.byte_offset < writer.size().await {
                    writer
                        .resize(repair.byte_offset)
                        .await
                        .map_err(Error::Runtime)?;
                    writer.sync().await.map_err(Error::Runtime)?;
                }
            }
        }

        // Seal every blob below the tail. Retained blobs must be contiguous: positions map to
        // blobs by arithmetic, so a gap would make some retained position unreadable.
        if let Some(&newest) = pending.keys().next_back() {
            if newest > tail_blob {
                return Err(Error::Corruption(format!(
                    "blobs > tail blob {tail_blob} exist (newest={newest})"
                )));
            }
        }
        let mut sealed = Vec::with_capacity(pending.len());
        let mut tail = None;
        let mut expected = pending.keys().next().copied();
        for (blob, writer) in pending {
            if expected != Some(blob) {
                return Err(Error::Corruption(format!(
                    "retained blobs must be contiguous (expected {expected:?}, got {blob})"
                )));
            }
            expected = blob.checked_add(1);
            if blob == tail_blob {
                tail = Some(Tail { blob, writer });
            } else {
                sealed.push(writer.seal().await.map_err(Error::Runtime)?);
            }
        }
        let tail = match tail {
            Some(tail) => tail,
            None => Tail {
                blob: tail_blob,
                writer: io.open(tail_blob).await?,
            },
        };

        // Bytes beyond the persisted recovery watermark may be readable after reopen without
        // being crash-durable, so the next commit/sync must force a data sync before advancing it.
        let dirty_from_blob =
            (recovery_watermark < size).then_some(recovery_watermark / items_per_blob);

        let metrics = Metrics::new(context);
        metrics.update(size, pruning_boundary, items_per_blob);

        Ok(Self::from_blobs(
            io,
            sealed,
            tail,
            metadata,
            size,
            pruning_boundary,
            dirty_from_blob,
            cfg.items_per_blob,
            metrics,
        ))
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
        // detect CLEAR_TARGET_KEY and complete the clear via the staged-clear path before
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

    /// Convert a global position to (blob, position_in_blob).
    #[inline]
    const fn position_to_blob(&self, position: u64) -> (u64, u64) {
        let blob = position / self.items_per_blob.get();
        let pos_in_blob = position % self.items_per_blob.get();
        (blob, pos_in_blob)
    }

    /// Make dirty blobs durable: sealed blobs through handles cloned from the current
    /// table, the tail through the writer.
    ///
    /// Blobs are synced concurrently. Ordering is not required for recovery: appends only add
    /// data, so committed blobs are never at risk, and recovery truncates at the first short or
    /// missing blob, so a crash that leaves a gap still recovers a contiguous prefix no shorter
    /// than the last completed commit.
    async fn flush_dirty_blobs(&mut self) -> Result<(), Error> {
        let Some(start_blob) = self.dirty_from_blob else {
            return Ok(());
        };
        let table = self.current_table();
        let start_blob = start_blob.max(table.base_blob);

        // Sync dirty sealed blobs concurrently through cloned handles.
        let mut dirty_sealed = Vec::new();
        for blob in start_blob..table.tail_blob() {
            let idx = (blob - table.base_blob) as usize;
            dirty_sealed.push(table.sealed[idx].clone());
        }
        try_join_all(dirty_sealed.iter().map(|sealed| sealed.sync()))
            .await
            .map_err(Error::Runtime)?;
        self.io.metrics.synced.inc_by(dirty_sealed.len() as u64);

        // Sync the tail.
        self.tail.writer.sync().await.map_err(Error::Runtime)?;
        self.io.metrics.synced.inc();
        Ok(())
    }

    /// Durably persists the current state of the table.
    ///
    /// Does not advance the recovery watermark, so external consumers may need to replay entries
    /// beyond the previous `sync()`. Use `sync()` to advance the watermark and to ensure that a
    /// crash after this call doesn't require any recovery.
    pub async fn commit(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.commit_timer();
        self.metrics.record_commit();
        self.flush_dirty_blobs().await?;
        self.dirty_from_blob = None;
        Ok(())
    }

    /// Durably persist the current state of the table, ensuring no recovery is required in the
    /// event of a crash following this call.
    ///
    /// Advances the recovery watermark to the current size.
    pub async fn sync(&mut self) -> Result<(), Error> {
        let _timer = self.metrics.sync_timer();
        self.metrics.sync_calls.inc();
        self.flush_dirty_blobs().await?;
        self.dirty_from_blob = None;
        Self::stage_metadata_entries(
            &mut self.metadata,
            self.items_per_blob.get(),
            self.pruning_boundary,
            self.size,
        );
        self.metadata.sync().await?;
        Ok(())
    }

    /// Return an owned snapshot of the journal. Bounds are frozen at creation; take a new
    /// reader to observe later appends.
    pub fn reader(&self) -> Reader<E, A> {
        let snapshot = self.shared.snapshot(self.items_per_blob);
        self.shared.readers.fetch_add(1, Ordering::Relaxed);
        Reader {
            snapshot,
            metrics: self.metrics.clone(),
            shared: self.shared.clone(),
            _phantom: PhantomData,
        }
    }

    /// Return the recovery watermark.
    pub(crate) fn recovery_watermark(&self) -> u64 {
        self.metadata
            .get(&RECOVERY_WATERMARK_KEY)
            .copied()
            .map(u64::from)
            .expect("recovery watermark must exist after init")
    }

    /// Return the total number of items in the journal, irrespective of pruning. The next value
    /// appended to the journal will be at this position.
    pub fn size(&self) -> u64 {
        self.shared.size.load(Ordering::Acquire)
    }

    /// Append a new item to the journal. Return the item's position in the journal, or error if the
    /// operation fails.
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
        if items.is_empty() {
            return Err(Error::EmptyAppend);
        }

        // Encode all items into a single contiguous buffer up front.
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

        let first_dirty_blob = self.size / self.items_per_blob.get();
        self.mark_dirty_from(first_dirty_blob);
        let mut written = 0;
        while written < items_count {
            let (blob, pos_in_blob) = self.position_to_blob(self.size);
            let remaining_space = (self.items_per_blob.get() - pos_in_blob) as usize;
            let batch_count = remaining_space.min(items_count - written);
            let start = written * A::SIZE;
            let end = start + batch_count * A::SIZE;
            let new_size = self
                .size
                .checked_add(batch_count as u64)
                .ok_or(Error::OffsetOverflow)?;
            let next_blob = if new_size.is_multiple_of(self.items_per_blob.get()) {
                Some(blob.checked_add(1).ok_or(Error::OffsetOverflow)?)
            } else {
                None
            };

            self.tail
                .writer
                .append(&items_buf[start..end])
                .await
                .map_err(Error::Runtime)?;
            self.size = new_size;
            written += batch_count;

            if let Some(next_blob) = next_blob {
                // Seal the just-filled tail and open the next blob as the new tail. This does
                // NOT fsync the old blob -- dirty tracking still covers it until commit/sync.
                self.roll_tail(next_blob).await?;
            }
        }

        // Publish only after the appended bytes and any rolled table are visible.
        self.shared.publish_size(self.size);
        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_blob.get());
        Ok(self.size - 1)
    }

    /// Seal the current tail (no fsync) and open `next_blob` as the new tail.
    async fn roll_tail(&mut self, next_blob: u64) -> Result<(), Error> {
        // Open the next tail first so a failure leaves the current tail untouched.
        let new_writer = self.io.open(next_blob).await?;
        self.io.metrics.tracked.inc();
        let new_reader = new_writer.reader();
        let old = std::mem::replace(
            &mut self.tail,
            Tail {
                blob: next_blob,
                writer: new_writer,
            },
        );
        let sealed = old.writer.seal().await.map_err(Error::Runtime)?;

        let current = self.current_table();
        let mut sealed_vec: Vec<Sealed<E::Blob>> = current.sealed.to_vec();
        sealed_vec.push(sealed);
        self.shared.publish_table(BlobTable {
            sealed: sealed_vec.into(),
            tail_reader: new_reader,
            ..current.successor()
        });
        Ok(())
    }

    /// Rewind the journal to the given `size`. Returns [Error::InvalidRewind] if the rewind point
    /// precedes the oldest retained element. The journal is not synced after rewinding.
    ///
    /// Returns [Error::BlobInUse] if the rewind target is a sealed historical blob and any
    /// [Reader] snapshot is outstanding: truncating in place could tear a reader's bytes. Retry
    /// after readers are dropped.
    ///
    /// # Warnings
    ///
    /// * This operation is not guaranteed to survive restarts until `commit()` or `sync()` is
    ///   called.
    /// * This operation is not atomic. Its on-disk updates are ordered (blobs removed
    ///   newest-to-oldest) so that restart recovery always rebuilds a contiguous retained prefix.
    pub async fn rewind(&mut self, size: u64) -> Result<(), Error> {
        match size.cmp(&self.size) {
            std::cmp::Ordering::Greater => return Err(Error::InvalidRewind(size)),
            std::cmp::Ordering::Equal => return Ok(()),
            std::cmp::Ordering::Less => {}
        }

        if size < self.pruning_boundary {
            return Err(Error::InvalidRewind(size));
        }

        let blob = size / self.items_per_blob.get();
        let pos_in_blob =
            size - first_in_blob(self.pruning_boundary, blob, self.items_per_blob.get())?;
        let byte_offset = pos_in_blob
            .checked_mul(Self::CHUNK_SIZE_U64)
            .ok_or(Error::OffsetOverflow)?;

        // Persist a lowered recovery watermark before blob state moves backward.
        if Self::lower_recovery_watermark(&mut self.metadata, size) {
            self.metadata.sync().await?;
        }

        if blob == self.tail.blob {
            // Shrink the tail in place. Racing readers get clean errors from the resize,
            // never torn bytes.
            let current_bytes = self.tail.writer.size().await;
            if byte_offset < current_bytes {
                self.tail
                    .writer
                    .resize(byte_offset)
                    .await
                    .map_err(Error::Runtime)?;
            }
            // Bump the version so racing readers cannot pair the stale size with this table.
            let current = self.current_table();
            self.shared.publish_table(current.successor());
        } else {
            self.rewind_to_sealed(blob, byte_offset).await?;
        }

        self.size = size;
        self.shared.publish_size(size);
        self.mark_dirty_from(blob);
        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_blob.get());

        Ok(())
    }

    /// Rewind into a sealed blob: demote it to the writable tail, truncated to `byte_offset`,
    /// discarding every newer blob.
    ///
    /// In-place truncation requires no outstanding [Reader] snapshots; `&mut self` prevents new
    /// ones. Returns [Error::BlobInUse] otherwise.
    async fn rewind_to_sealed(&mut self, blob: u64, byte_offset: u64) -> Result<(), Error> {
        let current = self.current_table();
        let idx = blob
            .checked_sub(current.base_blob)
            .map(|idx| idx as usize)
            .filter(|&idx| idx < current.sealed.len())
            .ok_or_else(|| Error::Corruption(format!("rewind target blob {blob} not retained")))?;

        if self.shared.readers.load(Ordering::Acquire) != 0 {
            return Err(Error::BlobInUse(blob));
        }
        let target = &current.sealed[idx];

        // Sync the target before destructive work so a crash recovers a size no shorter than
        // the rewind target.
        target.sync().await.map_err(Error::Runtime)?;
        self.io.metrics.synced.inc();

        // Reopen the target as the writable tail and truncate in place. The fresh Writer
        // gets a fresh page-cache id, so pages cached under the sealed handle's id are
        // unreachable.
        let new_writer = self.io.open(blob).await?;
        let current_bytes = new_writer.size().await;
        if byte_offset < current_bytes {
            new_writer
                .resize(byte_offset)
                .await
                .map_err(Error::Runtime)?;
        }
        let new_reader = new_writer.reader();

        // Remove newer blobs newest-first so a crash leaves a contiguous prefix: the old
        // tail, then sealed blobs down to the target.
        let old_tail = std::mem::replace(
            &mut self.tail,
            Tail {
                blob,
                writer: new_writer,
            },
        );
        let old_tail_blob = old_tail.blob;
        drop(old_tail);
        self.io.remove_blob(old_tail_blob).await?;
        self.io.metrics.tracked.dec();
        for s in ((blob + 1)..current.tail_blob()).rev() {
            self.io.remove_blob(s).await?;
            self.io.metrics.tracked.dec();
        }

        // Sealed history now ends below the target, which is the tail.
        self.shared.publish_table(BlobTable {
            sealed: current.sealed[..idx].to_vec().into(),
            tail_reader: new_reader,
            ..current.successor()
        });
        Ok(())
    }

    /// Return the location before which all items have been pruned.
    pub fn pruning_boundary(&self) -> u64 {
        self.shared.table.read().pruning_boundary
    }

    /// Allow the journal to prune items older than `min_item_pos`. The journal may not prune all
    /// such items in order to preserve blob boundaries, but the amount of such items will always be
    /// less than the configured number of items per blob. Returns true if any items were pruned.
    ///
    /// Readers holding earlier snapshots keep reading pruned blobs through their own handles;
    /// later snapshots observe [Error::ItemPruned].
    ///
    /// Note that this operation may NOT be atomic, however it's guaranteed not to leave gaps in the
    /// event of failure as items are always pruned in order from oldest to newest.
    pub async fn prune(&mut self, min_item_pos: u64) -> Result<bool, Error> {
        // Calculate the blob that would contain min_item_pos, capped to the tail (which is
        // guaranteed to exist by our invariant).
        let target_blob = min_item_pos / self.items_per_blob.get();
        let tail_blob = self.size / self.items_per_blob.get();
        let min_blob = std::cmp::min(target_blob, tail_blob);

        let current = self.current_table();
        if min_blob <= current.base_blob {
            return Ok(false);
        }

        let new_boundary = min_blob
            .checked_mul(self.items_per_blob.get())
            .ok_or(Error::OffsetOverflow)?;
        // Pruning boundary only moves forward.
        if self.pruning_boundary >= new_boundary {
            return Err(Error::Corruption(format!(
                "pruning boundary {} not before new oldest blob boundary {new_boundary}",
                self.pruning_boundary
            )));
        }
        self.pruning_boundary = new_boundary;

        // Publish the pruned table first; in-flight snapshot readers keep their handles.
        let drop_count = (min_blob - current.base_blob) as usize;
        self.shared.publish_table(BlobTable {
            base_blob: min_blob,
            sealed: current.sealed[drop_count..].to_vec().into(),
            pruning_boundary: new_boundary,
            ..current.successor()
        });

        // Physically remove the pruned blobs, oldest-first (gap-free on failure).
        for blob in current.base_blob..min_blob {
            self.io.remove_blob(blob).await?;
            self.io.metrics.tracked.dec();
            self.io.metrics.pruned.inc();
        }

        if let Some(dirty_from) = self.dirty_from_blob {
            self.dirty_from_blob = Some(dirty_from.max(min_blob));
        }
        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_blob.get());

        Ok(true)
    }

    /// Remove any persisted data created by the journal.
    ///
    /// # Crash Safety
    ///
    /// This operation is intended for final teardown and is not crash-safe. If interrupted,
    /// reopening the same partition may observe partially removed state. Use [Self::init_at_size]
    /// for a recoverable reset.
    pub async fn destroy(self) -> Result<(), Error> {
        // Remove the blobs and the partition itself.
        let current = self.shared.table.read().clone();
        drop(self.tail);
        for blob in current.base_blob..=current.tail_blob() {
            self.io.remove_blob(blob).await?;
        }
        self.io.remove_partition().await?;

        // Destroy metadata
        self.metadata.destroy().await?;

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
    pub(crate) async fn clear_to_size(&mut self, new_size: u64) -> Result<(), Error> {
        // Lower the watermark in-memory and stage the clear intent in the same metadata sync, so
        // external consumers never see a persisted recovery checkpoint beyond `new_size`.
        Self::lower_recovery_watermark(&mut self.metadata, new_size);
        self.metadata.put(CLEAR_TARGET_KEY, new_size.into());
        self.metadata.sync().await?;

        // Remove every blob, then open a fresh tail and publish the reset table.
        let current = self.current_table();
        let new_tail_blob = new_size / self.items_per_blob.get();
        for blob in current.base_blob..=current.tail_blob() {
            self.io.remove_blob(blob).await?;
        }
        let _ = self.io.metrics.tracked.try_set(0);
        let new_writer = self.io.open(new_tail_blob).await?;
        self.io.metrics.tracked.inc();
        let new_reader = new_writer.reader();
        self.tail = Tail {
            blob: new_tail_blob,
            writer: new_writer,
        };
        self.shared.publish_table(BlobTable {
            base_blob: new_tail_blob,
            sealed: Vec::new().into(),
            tail_reader: new_reader,
            pruning_boundary: new_size,
            ..current.successor()
        });
        self.size = new_size;
        self.pruning_boundary = new_size;
        self.shared.publish_size(new_size);
        self.dirty_from_blob = None;

        // Complete the clear in metadata.
        Self::stage_pruning_boundary_metadata(
            &mut self.metadata,
            self.items_per_blob.get(),
            new_size,
        );
        self.metadata.put(RECOVERY_WATERMARK_KEY, new_size.into());
        self.metadata.remove(&CLEAR_TARGET_KEY);
        self.metadata.sync().await?;

        self.metrics
            .update(self.size, self.pruning_boundary, self.items_per_blob.get());
        Ok(())
    }

    /// Durably stage a clear to `new_size` without completing it.
    ///
    /// This lowers the recovery watermark and persists `CLEAR_TARGET_KEY`, leaving a recoverable
    /// intent so a caller can clear dependent sibling state before calling `clear_to_size` to
    /// finish. If a crash interrupts the sequence, the next `init` completes the staged clear.
    /// The follow-up `clear_to_size` re-stages the same target idempotently.
    #[commonware_macros::stability(ALPHA)]
    pub(super) async fn stage_clear_intent(&mut self, new_size: u64) -> Result<(), Error> {
        Self::lower_recovery_watermark(&mut self.metadata, new_size);
        self.metadata.put(CLEAR_TARGET_KEY, new_size.into());
        self.metadata.sync().await?;
        Ok(())
    }

    /// Test helper: Read the item at the given position.
    #[cfg(test)]
    pub(crate) async fn read(&self, pos: u64) -> Result<A, Error> {
        self.reader().read(pos).await
    }

    /// Test helper: Return the bounds of the journal.
    #[cfg(test)]
    pub(crate) fn bounds(&self) -> std::ops::Range<u64> {
        use super::Reader as _;
        self.reader().bounds()
    }

    /// Test helper: Get the oldest blob from the blob store.
    #[cfg(test)]
    pub(crate) fn test_oldest_blob(&self) -> Option<u64> {
        Some(self.shared.table.read().base_blob)
    }

    /// Test helper: Get the newest blob from the blob store.
    #[cfg(test)]
    pub(crate) fn test_newest_blob(&self) -> Option<u64> {
        Some(self.shared.table.read().tail_blob())
    }

    /// Test helper: Make one blob durable (sealed history or the tail).
    #[cfg(test)]
    pub(crate) async fn test_sync_blob(&self, blob: u64) -> Result<(), Error> {
        let table = self.current_table();
        match table.handle(blob) {
            Some(state::BlobHandle::Sealed(sealed)) => sealed.sync().await.map_err(Error::Runtime),
            Some(state::BlobHandle::Tail(_)) => self.tail.writer.sync().await.map_err(Error::Runtime),
            None => Ok(()),
        }
    }

    /// Test helper: Set and persist the recovery watermark directly.
    #[cfg(test)]
    pub(crate) async fn test_set_recovery_watermark(
        &mut self,
        watermark: u64,
    ) -> Result<(), Error> {
        self.metadata.put(RECOVERY_WATERMARK_KEY, watermark.into());
        self.metadata.sync().await?;
        Ok(())
    }
}

// Implement Contiguous trait for fixed-length journals
impl<E: Context, A: CodecFixedShared> super::Contiguous for Journal<E, A> {
    type Item = A;

    async fn reader(&self) -> impl super::Reader<Item = A> + '_ {
        Self::reader(self)
    }

    async fn size(&self) -> u64 {
        Self::size(self)
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

    async fn commit(&mut self) -> Result<(), Error> {
        self.commit().await
    }

    async fn sync(&mut self) -> Result<(), Error> {
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

