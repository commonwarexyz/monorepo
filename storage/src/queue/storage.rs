//! Queue storage implementation.

use super::{Error, cursor::Cursor, metrics::Metrics};
use crate::{
    Context,
    journal::contiguous::{Contiguous as _, variable},
};
use commonware_codec::CodecShared;
use commonware_macros::boxed;
use commonware_runtime::{
    buffer::paged::CacheRef,
    telemetry::metrics::{Gauge, GaugeExt as _},
};
use commonware_utils::channel::watch;
use std::{
    num::{NonZeroU64, NonZeroUsize},
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::debug;

/// Configuration for [Queue].
#[derive(Clone)]
pub struct Config<C> {
    /// The storage partition name for the queue's journal.
    pub partition: String,

    /// The number of items to store in each journal section.
    ///
    /// Larger values reduce file overhead but increase minimum pruning granularity.
    /// Once set, this value cannot be changed across restarts.
    pub items_per_section: NonZeroU64,

    /// Optional zstd compression level for stored items.
    ///
    /// If set, items will be compressed before storage. Higher values provide
    /// better compression but use more CPU.
    ///
    /// Keep the choice between `None` and `Some(_)` fixed while stored items are retained.
    /// Only the compression level may change between initializations when compression is enabled.
    pub compression: Option<u8>,

    /// Codec configuration for encoding/decoding items.
    pub codec_config: C,

    /// Page cache for buffering reads from the underlying journal.
    pub page_cache: CacheRef,

    /// Write buffer size for each section.
    pub write_buffer: NonZeroUsize,

    /// Buffer size for sequential reads during recovery.
    pub replay_buffer: NonZeroUsize,
}

/// A published view of the queue's items.
type Snapshot<E, V> = Arc<variable::Reader<'static, E, V>>;

/// A durable, at-least-once delivery queue with per-item acknowledgment.
///
/// Items are durably stored in a journal and survive crashes. [Queue::init] returns the queue,
/// which writes items, and its [Reader], which delivers them. The reader must acknowledge each
/// item individually after processing. Items can be acknowledged out of order, enabling parallel
/// processing.
///
/// # Operations
///
/// - [append](Self::append) / [commit](Self::commit): Write items to the journal, then persist
///   them and publish them to the reader. Appended items are lost on restart if not committed.
/// - [enqueue](Self::enqueue): Append + commit in one step. The item is durable before return.
/// - [sync](Self::sync): Commit, then prune completed sections below the reader's ack floor.
/// - [Reader::recv] / [Reader::try_recv]: Return the next unacked committed item in FIFO order.
/// - [Reader::ack] / [Reader::ack_up_to]: Mark items as processed (in-memory only).
///
/// # Acknowledgment
///
/// Acks are tracked in-memory with an `ack_floor` (all positions below are acked)
/// plus an [RMap](crate::rmap::RMap) of acked positions above the floor. When items are acked
/// contiguously from the floor, the floor advances automatically.
///
/// Acks are **not** persisted. The durable equivalent is the journal's pruning
/// boundary, advanced by [sync](Self::sync). On restart, all non-pruned
/// items are re-delivered regardless of prior ack state.
///
/// # Crash Recovery
///
/// On restart, `ack_floor` is set to the journal's pruning boundary.
/// Items that were pruned are gone. Everything else is re-delivered.
/// Applications must handle duplicates (idempotent processing).
///
/// Storage-mutating functions consume the queue and return it only on success: an error (or a
/// dropped future) destroys the handle. The reader then delivers every published item and returns
/// `None`.
pub struct Queue<E: Context, V: CodecShared> {
    /// The underlying journal storing queue items.
    journal: variable::Journal<E, V>,

    /// Total enqueued items.
    tip: Gauge,

    /// Bounds of the last published snapshot.
    published: Range<u64>,

    /// Publishes snapshots to the reader.
    snapshots: watch::Sender<Snapshot<E, V>>,

    /// The reader's ack floor.
    floor: Arc<AtomicU64>,
}

impl<E: Context, V: CodecShared> Queue<E, V> {
    /// Initialize a queue from storage, returning it with its [Reader].
    ///
    /// On first initialization, creates an empty queue. On restart, the reader begins from the
    /// journal's pruning boundary (providing at-least-once delivery for all non-pruned items).
    /// Both handles must be dropped before the queue is reopened.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying journal cannot be initialized.
    #[boxed]
    pub async fn init(context: E, cfg: Config<V::Cfg>) -> Result<(Self, Reader<E, V>), Error> {
        // Initialize metrics before creating sub-contexts
        let metrics = Metrics::init(&context);

        // Recover the journal that backs the queue's retained items.
        let journal = variable::Journal::init(
            context.child("journal"),
            variable::Config {
                partition: cfg.partition,
                items_per_section: cfg.items_per_section,
                compression: cfg.compression,
                codec_config: cfg.codec_config,
                page_cache: cfg.page_cache,
                write_buffer: cfg.write_buffer,
                replay_buffer: cfg.replay_buffer,
            },
        )
        .await?;

        // On restart, the ack floor is the pruning boundary (items below are deleted).
        // In-memory acknowledgements are lost on restart.
        let bounds = journal.bounds();
        debug!(floor = bounds.start, size = bounds.end, "queue initialized");
        let _ = metrics.tip.try_set(bounds.end);
        let cursor = Cursor::new(bounds.start, metrics.next, metrics.floor);

        // Share the recovered view and the acknowledgement floor between the queue and its
        // reader.
        let (journal, snapshot) = journal.snapshot().await?;
        let snapshot = Arc::new(snapshot);
        let (sender, receiver) = watch::channel(snapshot.clone());
        let floor = Arc::new(AtomicU64::new(bounds.start));
        let queue = Self {
            journal,
            tip: metrics.tip,
            published: bounds,
            snapshots: sender,
            floor: floor.clone(),
        };
        let reader = Reader {
            snapshot,
            snapshots: receiver,
            cursor,
            floor,
        };
        Ok((queue, reader))
    }

    /// Append and commit an item, returning its position. The reader can receive the item once
    /// this returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(self, item: V) -> Result<(Self, u64), Error> {
        let (queue, pos) = self.append(item).await?;
        let queue = queue.commit().await?;
        debug!(position = pos, "enqueued item");
        Ok((queue, pos))
    }

    /// Append a batch of items with a single commit, returning positions `[start, end)`. The
    /// reader can receive the items once this returns.
    ///
    /// # Errors
    ///
    /// Returns an error if any append or the final commit fails.
    pub async fn enqueue_bulk(
        mut self,
        items: impl IntoIterator<Item = V>,
    ) -> Result<(Self, Range<u64>), Error> {
        // Append the batch before publishing it to the reader.
        let start = self.journal.size();
        for item in items {
            (self, _) = self.append(item).await?;
        }

        // Only a nonempty batch needs a commit.
        let end = self.journal.size();
        if end > start {
            self = self.commit().await?;
        }
        debug!(start, end, "enqueued bulk");
        Ok((self, start..end))
    }

    /// Append an item without committing, returning its position. The reader can receive the
    /// item after the next [Self::commit] or [Self::sync].
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn append(mut self, item: V) -> Result<(Self, u64), Error> {
        let pos;
        (self.journal, pos) = self.journal.append(&item).await?;
        let _ = self.tip.try_set(pos + 1);
        debug!(position = pos, "appended item");
        Ok((self, pos))
    }

    /// Durably persist appended items and publish them to the reader.
    ///
    /// This does not persist acknowledgements. For a stronger guarantee that eliminates potential
    /// recovery and prunes acknowledged items, use [Self::sync] instead.
    pub async fn commit(mut self) -> Result<Self, Error> {
        self.journal = self.journal.commit().await?;
        self.publish().await
    }

    /// Durably persist the queue, guaranteeing the current state will survive a crash, and that
    /// no recovery will be needed on startup.
    ///
    /// This also prunes items below the reader's ack floor and publishes the result to the reader.
    pub async fn sync(mut self) -> Result<Self, Error> {
        // Make appended items durable before pruning their predecessors.
        self.journal = self.journal.sync().await?;

        // Sample the reader's monotonic floor. A stale value only delays pruning.
        let floor = self.floor.load(Ordering::Relaxed);
        (self.journal, _) = self.journal.prune(floor).await?;

        // Publish a view with the retained bounds.
        self.publish().await
    }

    /// Returns the total number of items that have been appended.
    pub fn size(&self) -> u64 {
        self.journal.size()
    }

    /// Publish a snapshot of the journal if its bounds changed since the last one.
    async fn publish(mut self) -> Result<Self, Error> {
        let bounds = self.journal.bounds();
        if bounds == self.published {
            return Ok(self);
        }

        // Capture the new view before publishing its bounds and waking the reader.
        let snapshot;
        (self.journal, snapshot) = self.journal.snapshot().await?;
        self.published = bounds;
        self.snapshots.send_replace(Arc::new(snapshot));
        Ok(self)
    }

    /// Destroy the queue, removing all data from disk.
    #[boxed]
    pub async fn destroy(self) -> Result<(), Error> {
        self.journal.destroy().await?;
        Ok(())
    }
}

impl<E: Context, V: CodecShared> std::fmt::Debug for Queue<E, V> {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Queue")
            .field("size", &self.size())
            .finish_non_exhaustive()
    }
}

/// Delivers a [Queue]'s committed items and tracks their acknowledgement.
///
/// Acknowledgements are in-memory, and [Queue::sync] prunes items below the ack floor.
pub struct Reader<E: Context, V: CodecShared> {
    /// The snapshot items are delivered from.
    snapshot: Snapshot<E, V>,

    /// Receives snapshots from the queue.
    snapshots: watch::Receiver<Snapshot<E, V>>,

    /// Delivery and acknowledgement state.
    cursor: Cursor,

    /// The ack floor shared with the queue.
    floor: Arc<AtomicU64>,
}

impl<E: Context, V: CodecShared> Reader<E, V> {
    /// Receive the next unacknowledged item, waiting if necessary.
    ///
    /// This method is designed for use with `select!`. It will:
    /// 1. Return immediately if an unacked item has been published
    /// 2. Wait for the queue to publish new items otherwise
    /// 3. Return `None` once the queue is dropped and every published item has been delivered
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn recv(&mut self) -> Result<Option<(u64, V)>, Error> {
        // Drain published items before waiting for the next snapshot or the queue's departure.
        loop {
            if let Some(item) = self.try_recv().await? {
                return Ok(Some(item));
            }

            // `try_recv` has seen the newest snapshot, so wait for the next one. `changed` marks it
            // seen, so move to it here.
            if self.snapshots.changed().await.is_err() {
                return Ok(None);
            }
            self.snapshot = self.snapshots.borrow_and_update().clone();
        }
    }

    /// Try to dequeue the next unacknowledged item without waiting.
    ///
    /// Returns `None` immediately if no unacked item has been published.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn try_recv(&mut self) -> Result<Option<(u64, V)>, Error> {
        // Move to the newest snapshot before reading, releasing blobs the queue has pruned. A
        // closed channel still holds the queue's final snapshot.
        if self.snapshots.has_changed().unwrap_or(true) {
            self.snapshot = self.snapshots.borrow_and_update().clone();
        }
        self.cursor.dequeue(&*self.snapshot).await
    }

    /// Returns whether a specific position has been acknowledged.
    pub fn is_acked(&self, position: u64) -> bool {
        self.cursor.is_acked(position)
    }

    /// Mark the item at `position` as processed (in-memory only). The item is skipped on
    /// subsequent receives. If this creates a contiguous run from the ack floor, the floor
    /// advances.
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `position` has not been published.
    pub fn ack(&mut self, position: u64) -> Result<(), Error> {
        self.cursor.ack(position, self.published())?;
        self.floor.store(self.cursor.ack_floor(), Ordering::Relaxed);
        Ok(())
    }

    /// Acknowledge all items in `[ack_floor, up_to)` by advancing the floor directly. More
    /// efficient than calling [Self::ack] in a loop.
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `up_to` exceeds the published items.
    pub fn ack_up_to(&mut self, up_to: u64) -> Result<(), Error> {
        self.cursor.ack_up_to(up_to, self.published())?;
        self.floor.store(self.cursor.ack_floor(), Ordering::Relaxed);
        Ok(())
    }

    /// Returns the current ack floor.
    ///
    /// All items at positions less than this value are considered acknowledged.
    pub const fn ack_floor(&self) -> u64 {
        self.cursor.ack_floor()
    }

    /// Returns the current read position.
    ///
    /// This is the position of the next item [Self::try_recv] will check.
    pub const fn read_position(&self) -> u64 {
        self.cursor.read_position()
    }

    /// Returns whether every published item has been acknowledged.
    pub fn is_empty(&self) -> bool {
        self.cursor.is_empty(self.published())
    }

    /// Reset the read position to the ack floor so the reader re-delivers every unacknowledged
    /// item.
    pub fn reset(&mut self) {
        self.cursor.reset();
    }

    /// Returns the number of published items.
    fn published(&self) -> u64 {
        self.snapshots.borrow().bounds().end
    }

    /// Returns the number of published items not yet read (test-only).
    #[cfg(test)]
    fn pending(&self) -> u64 {
        self.published().saturating_sub(self.cursor.read_position())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::RangeCfg;
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{
        BufferPooler, Metrics as _, Runner, Spawner, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::NonZeroU16;

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_config(partition: &str, pooler: &impl BufferPooler) -> Config<(RangeCfg<usize>, ())> {
        Config {
            partition: partition.into(),
            items_per_section: NZU64!(10),
            compression: None,
            codec_config: ((0..).into(), ()),
            page_cache: CacheRef::from_pooler(pooler, PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(4096),
            replay_buffer: NZUsize!(4096),
        }
    }

    async fn init<E: Context>(
        context: E,
        cfg: Config<(RangeCfg<usize>, ())>,
    ) -> Result<(Queue<E, Vec<u8>>, Reader<E, Vec<u8>>), Error> {
        Queue::init(context, cfg).await
    }

    fn acked_above_count<E: Context, V: CodecShared>(reader: &Reader<E, V>) -> usize {
        reader.cursor.acked_above_count()
    }

    #[test_traced]
    fn test_basic_enqueue_dequeue() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_basic", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Queue should be empty initially
            assert!(reader.is_empty());
            assert_eq!(reader.pending(), 0);
            assert_eq!(queue.size(), 0);

            // Enqueue items
            let pos0;
            (queue, pos0) = queue.enqueue(b"item0".to_vec()).await.unwrap();
            let pos1;
            (queue, pos1) = queue.enqueue(b"item1".to_vec()).await.unwrap();
            let pos2;
            (queue, pos2) = queue.enqueue(b"item2".to_vec()).await.unwrap();

            assert_eq!(pos0, 0);
            assert_eq!(pos1, 1);
            assert_eq!(pos2, 2);
            assert_eq!(queue.size(), 3);
            assert_eq!(reader.pending(), 3);
            assert!(!reader.is_empty());

            // Dequeue items
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, b"item0");
            assert_eq!(reader.pending(), 2);

            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 1);
            assert_eq!(item, b"item1");
            assert_eq!(reader.pending(), 1);

            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 2);
            assert_eq!(item, b"item2");
            assert_eq!(reader.pending(), 0);

            // Queue still has unacked items
            assert!(!reader.is_empty());
            assert!(reader.try_recv().await.unwrap().is_none());
        });
    }

    #[test_traced]
    fn test_append_commit_batch() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_batch", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Append multiple items, then commit once
            for i in 0..5u8 {
                (queue, _) = queue.append(vec![i]).await.unwrap();
            }
            let mut queue = queue.commit().await.unwrap();
            assert_eq!(queue.size(), 5);

            // Dequeue and verify order
            for i in 0..5 {
                let (pos, item) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
            }

            // Mix batch and single enqueue
            for i in 5..8u8 {
                (queue, _) = queue.append(vec![i]).await.unwrap();
            }
            let queue = queue.commit().await.unwrap();
            let (queue, _) = queue.enqueue(vec![8]).await.unwrap();
            assert_eq!(queue.size(), 9);

            reader.ack_up_to(9).unwrap();
            assert!(reader.is_empty());
        });
    }

    #[test_traced]
    fn test_append_commit_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_batch_persist", &context);

            {
                let (mut queue, _reader) =
                    Queue::<_, Vec<u8>>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();
                for i in 0..4u8 {
                    (queue, _) = queue.append(vec![i]).await.unwrap();
                }
                let queue = queue.commit().await.unwrap();
                queue.sync().await.unwrap();
            }

            {
                let (queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("second"), cfg)
                    .await
                    .unwrap();
                assert_eq!(queue.size(), 4);
                for i in 0..4 {
                    let (pos, item) = reader.try_recv().await.unwrap().unwrap();
                    assert_eq!(pos, i);
                    assert_eq!(item, vec![i as u8]);
                }
            }
        });
    }

    #[test_traced]
    fn test_commit_after_sync_recovers_without_second_sync() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_commit_after_sync_recovery", &context);

            {
                let (mut queue, _reader) =
                    Queue::<_, Vec<u8>>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();

                // Establish a synced baseline so the recovery watermark is behind the next commit.
                (queue, _) = queue.append(b"synced".to_vec()).await.unwrap();
                queue = queue.commit().await.unwrap();
                queue = queue.sync().await.unwrap();

                // Commit later data without syncing; reopen must replay it from the old watermark.
                (queue, _) = queue.append(b"committed-a".to_vec()).await.unwrap();
                (queue, _) = queue.append(b"committed-b".to_vec()).await.unwrap();
                queue.commit().await.unwrap();
            }

            let (queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("second"), cfg)
                .await
                .unwrap();
            assert_eq!(queue.size(), 3);
            for (expected_pos, expected_item) in [
                (0, b"synced".to_vec()),
                (1, b"committed-a".to_vec()),
                (2, b"committed-b".to_vec()),
            ] {
                let (pos, item) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(pos, expected_pos);
                assert_eq!(item, expected_item);
            }

            queue.destroy().await.unwrap();
        });
    }

    #[test_traced]
    fn test_sequential_ack() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_seq_ack", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..5u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Dequeue and ack sequentially
            for i in 0..5 {
                let (pos, _) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                reader.ack(pos).unwrap();
                assert_eq!(reader.ack_floor(), i + 1);
            }

            // All items acked
            assert!(reader.is_empty());
            assert_eq!(reader.ack_floor(), 5);
        });
    }

    #[test_traced]
    fn test_out_of_order_ack() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ooo_ack", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..5u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Dequeue all
            for _ in 0..5 {
                reader.try_recv().await.unwrap();
            }

            // Ack out of order: 2, 4, 1, 3, 0
            reader.ack(2).unwrap();
            assert_eq!(reader.ack_floor(), 0); // Floor doesn't move
            assert!(reader.is_acked(2));

            reader.ack(4).unwrap();
            assert_eq!(reader.ack_floor(), 0);
            assert!(reader.is_acked(4));

            reader.ack(1).unwrap();
            assert_eq!(reader.ack_floor(), 0);

            reader.ack(3).unwrap();
            assert_eq!(reader.ack_floor(), 0);

            // Ack 0 - floor should advance to 5 (consuming 1,2,3,4)
            reader.ack(0).unwrap();
            assert_eq!(reader.ack_floor(), 5);
            assert!(reader.is_empty());
        });
    }

    #[test_traced]
    fn test_ack_up_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Batch ack items 0-4
            reader.ack_up_to(5).unwrap();
            assert_eq!(reader.ack_floor(), 5);

            // Items 0-4 should be acked
            for i in 0..5 {
                assert!(reader.is_acked(i));
            }
            // Items 5-9 should not be acked
            for i in 5..10 {
                assert!(!reader.is_acked(i));
            }

            // Dequeue should start at 5
            let (p, _) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 5);
        });
    }

    #[test_traced]
    fn test_ack_up_to_with_existing_acks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_existing", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack some items out of order first
            reader.ack(7).unwrap();
            reader.ack(8).unwrap();
            assert_eq!(acked_above_count(&reader), 2);

            // Batch ack up to 5
            reader.ack_up_to(5).unwrap();
            assert_eq!(reader.ack_floor(), 5);
            assert_eq!(acked_above_count(&reader), 2);

            // Now batch ack up to 9 - should consume the acked_above entries
            reader.ack_up_to(9).unwrap();
            assert_eq!(reader.ack_floor(), 9);
            assert_eq!(acked_above_count(&reader), 0);
        });
    }

    #[test_traced]
    fn test_ack_up_to_coalesces_with_acked_above() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_coalesce", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack items 5, 6, 7 first
            reader.ack(5).unwrap();
            reader.ack(6).unwrap();
            reader.ack(7).unwrap();
            assert_eq!(reader.ack_floor(), 0);

            // Batch ack up to 5 - should coalesce with 5, 6, 7
            reader.ack_up_to(5).unwrap();
            assert_eq!(reader.ack_floor(), 8); // Consumed 5, 6, 7
        });
    }

    #[test_traced]
    fn test_ack_up_to_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_errors", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            (queue, _) = queue.enqueue(b"item0".to_vec()).await.unwrap();
            let (_queue, _) = queue.enqueue(b"item1".to_vec()).await.unwrap();

            // Can't ack_up_to beyond queue size
            let err = reader.ack_up_to(5).unwrap_err();
            assert!(matches!(err, Error::PositionOutOfRange(5, 2)));

            // Can ack_up_to at queue size
            reader.ack_up_to(2).unwrap();
            assert_eq!(reader.ack_floor(), 2);

            // Acking up_to at or below floor is a no-op
            reader.ack_up_to(1).unwrap();
            assert_eq!(reader.ack_floor(), 2);
        });
    }

    #[test_traced]
    fn test_dequeue_skips_acked() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_skip_acked", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items 0-4
            for i in 0..5u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack items 1 and 3 before reading
            reader.ack(1).unwrap();
            reader.ack(3).unwrap();

            // Dequeue should skip 1 and 3
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, vec![0]);

            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 2); // Skipped 1
            assert_eq!(item, vec![2]);

            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 4); // Skipped 3
            assert_eq!(item, vec![4]);

            assert!(reader.try_recv().await.unwrap().is_none());
        });
    }

    #[test_traced]
    fn test_ack_errors() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_errors", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            (queue, _) = queue.enqueue(b"item0".to_vec()).await.unwrap();
            let (_queue, _) = queue.enqueue(b"item1".to_vec()).await.unwrap();

            // Can't ack position beyond queue size
            let err = reader.ack(5).unwrap_err();
            assert!(matches!(err, Error::PositionOutOfRange(5, 2)));

            // Can ack unread items
            reader.ack(1).unwrap();
            assert!(reader.is_acked(1));

            // Double ack is a no-op
            reader.ack(1).unwrap();
        });
    }

    #[test_traced]
    fn test_prune() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_prune", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items (more than items_per_section to test pruning)
            for i in 0..25u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }
            let _queue = queue.sync().await.unwrap();

            // Read and ack some items
            for i in 0..15 {
                reader.try_recv().await.unwrap();
                reader.ack(i).unwrap();
            }
            assert_eq!(reader.ack_floor(), 15);

            // Items 15+ should still be readable
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 15);
            assert_eq!(item, vec![15]);
        });
    }

    #[test_traced]
    fn test_ack_across_sections() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_multi_prune", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue many items across multiple sections (items_per_section = 10)
            for i in 0..50u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }
            let _queue = queue.sync().await.unwrap();

            // First batch: ack items 0-14
            for i in 0..15 {
                reader.try_recv().await.unwrap();
                reader.ack(i).unwrap();
            }
            assert_eq!(reader.ack_floor(), 15);

            // Verify items 15+ still readable
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 15);
            assert_eq!(item, vec![15]);

            // Second batch: ack items 15-29
            reader.ack(15).unwrap();
            for i in 16..30 {
                reader.try_recv().await.unwrap();
                reader.ack(i).unwrap();
            }
            assert_eq!(reader.ack_floor(), 30);

            // Verify items 30+ still readable
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 30);
            assert_eq!(item, vec![30]);

            // Third batch: ack remaining items
            reader.ack(30).unwrap();
            for i in 31..50 {
                reader.try_recv().await.unwrap();
                reader.ack(i).unwrap();
            }
            assert_eq!(reader.ack_floor(), 50);

            // Queue should be empty now
            assert!(reader.is_empty());
            assert!(reader.try_recv().await.unwrap().is_none());
        });
    }

    #[test_traced]
    fn test_crash_recovery_replays_from_pruning_boundary() {
        // On restart, ack_floor = pruning_boundary. Items not pruned are re-delivered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_recovery_replay", &context);

            // First session: enqueue items, ack some (but not enough to prune)
            {
                let (mut queue, mut reader) =
                    Queue::<_, Vec<u8>>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();

                for i in 0..5u8 {
                    (queue, _) = queue.enqueue(vec![i]).await.unwrap();
                }

                // Ack items 0, 1, 2 - but items_per_section=10, so no pruning
                reader.ack(0).unwrap();
                reader.ack(1).unwrap();
                reader.ack(2).unwrap();
                assert_eq!(reader.ack_floor(), 3);

                queue.sync().await.unwrap();
            }

            // Second session: all items are re-delivered (no pruning occurred)
            {
                let (_queue, mut reader) =
                    Queue::<_, Vec<u8>>::init(context.child("second"), cfg.clone())
                        .await
                        .unwrap();

                // ack_floor = pruning_boundary = 0 (nothing was pruned)
                assert_eq!(reader.ack_floor(), 0);

                // All items re-delivered
                for i in 0..5 {
                    let (p, _) = reader.try_recv().await.unwrap().unwrap();
                    assert_eq!(p, i);
                }
            }
        });
    }

    #[test_traced]
    fn test_crash_recovery_with_pruning() {
        // Items pruned before crash are not re-delivered.
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_recovery_pruned", &context);

            // First session: enqueue many items, ack enough to trigger pruning
            let expected_pruning_boundary = {
                let (mut queue, mut reader) =
                    Queue::<_, Vec<u8>>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();

                // Enqueue items across multiple sections (items_per_section = 10)
                for i in 0..25u8 {
                    (queue, _) = queue.enqueue(vec![i]).await.unwrap();
                }

                // Ack items 0-14 to advance floor past section 0
                for i in 0..15 {
                    reader.ack(i).unwrap();
                }
                assert_eq!(reader.ack_floor(), 15);

                // Sync triggers pruning
                queue = queue.sync().await.unwrap();

                // Verify pruning occurred
                let pruning_boundary = queue.journal.bounds().start;
                assert!(pruning_boundary > 0, "expected some pruning to occur");

                pruning_boundary
            };

            // Second session: only non-pruned items are available
            {
                let (queue, mut reader) =
                    Queue::<_, Vec<u8>>::init(context.child("second"), cfg.clone())
                        .await
                        .unwrap();

                // ack_floor = pruning_boundary (items 0-9 were pruned)
                let pruning_boundary = queue.journal.bounds().start;
                assert_eq!(reader.ack_floor(), pruning_boundary);
                assert_eq!(pruning_boundary, expected_pruning_boundary);

                // Items from pruning_boundary to 24 are re-delivered
                for i in pruning_boundary..25 {
                    let (p, item) = reader.try_recv().await.unwrap().unwrap();
                    assert_eq!(p, i);
                    assert_eq!(item, vec![i as u8]);
                }

                assert!(reader.try_recv().await.unwrap().is_none());
            }
        });
    }

    #[test_traced]
    fn test_reset() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_reset", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..5u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Read some
            reader.try_recv().await.unwrap();
            reader.try_recv().await.unwrap();
            reader.try_recv().await.unwrap();
            assert_eq!(reader.read_position(), 3);

            // Reset without ack - should go back to 0
            reader.reset();
            assert_eq!(reader.read_position(), 0);

            // Verify we can re-read
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 0);
            assert_eq!(item, vec![0]);
        });
    }

    #[test_traced]
    fn test_reset_with_ack() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_reset_ack", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Read and ack some
            for i in 0..5 {
                reader.try_recv().await.unwrap();
                reader.ack(i).unwrap();
            }
            assert_eq!(reader.ack_floor(), 5);
            assert_eq!(reader.read_position(), 5);

            // Read a few more
            reader.try_recv().await.unwrap();
            reader.try_recv().await.unwrap();
            assert_eq!(reader.read_position(), 7);

            // Reset - should go back to ack floor
            reader.reset();
            assert_eq!(reader.read_position(), 5);

            // Next dequeue should return item 5
            let (p, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(p, 5);
            assert_eq!(item, vec![5]);
        });
    }

    #[test_traced]
    fn test_empty_queue_operations() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_empty", &context);
            let (queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Operations on empty queue
            assert!(reader.is_empty());
            assert!(reader.try_recv().await.unwrap().is_none());
            let _queue = queue.sync().await.unwrap();
            reader.reset();
        });
    }

    #[test_traced]
    fn test_persistence() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_persist", &context);

            // First session
            {
                let (mut queue, _reader) =
                    Queue::<_, Vec<u8>>::init(context.child("first"), cfg.clone())
                        .await
                        .unwrap();

                (queue, _) = queue.enqueue(b"item0".to_vec()).await.unwrap();
                (queue, _) = queue.enqueue(b"item1".to_vec()).await.unwrap();
                queue.sync().await.unwrap();
            }

            // Second session - data should persist
            {
                let (queue, mut reader) =
                    Queue::<_, Vec<u8>>::init(context.child("second"), cfg.clone())
                        .await
                        .unwrap();

                assert_eq!(queue.size(), 2);

                let (_, item) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(item, b"item0");

                let (_, item) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(item, b"item1");
            }
        });
    }

    #[test_traced]
    fn test_large_queue_with_sparse_acks() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_sparse", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue many items
            for i in 0..100u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack every 3rd item (sparse acking)
            for i in (0..100).step_by(3) {
                reader.ack(i).unwrap();
            }

            // Dequeue should skip acked items
            let mut received = Vec::new();
            while let Some((pos, _)) = reader.try_recv().await.unwrap() {
                received.push(pos);
            }

            // Should have received all items not divisible by 3
            let expected: Vec<u64> = (0..100).filter(|x| x % 3 != 0).collect();
            assert_eq!(received, expected);
        });
    }

    #[test_traced]
    fn test_acked_above_coalescing() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_coalesce", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            // Enqueue items
            for i in 0..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Ack items 1-8 (not 0)
            for i in 1..9 {
                reader.ack(i).unwrap();
            }

            // Acked_above should have items 1-8
            assert_eq!(reader.ack_floor(), 0);
            assert!(acked_above_count(&reader) > 0);

            // Now ack 0 - floor should advance to 9, consuming all acked_above
            reader.ack(0).unwrap();
            assert_eq!(reader.ack_floor(), 9);
            assert_eq!(acked_above_count(&reader), 0);
        });
    }

    #[test_traced]
    fn test_ack_up_to_past_read_pos() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_ack_up_to_past_read_pos", &context);
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(context.child("storage"), cfg)
                .await
                .unwrap();

            for i in 0..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }

            // Read only 3 items
            for _ in 0..3 {
                reader.try_recv().await.unwrap();
            }
            assert_eq!(reader.read_position(), 3);

            // Batch ack past read position
            reader.ack_up_to(7).unwrap();
            assert_eq!(reader.ack_floor(), 7);

            // Dequeue should skip 3-6 and return 7
            let (pos, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(pos, 7);
            assert_eq!(item, vec![7]);
        });
    }

    #[test_traced]
    fn test_metrics() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test-metrics", &context);
            let ctx = context.child("test_metrics");
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(ctx, cfg).await.unwrap();

            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_tip 0"),
                "expected tip 0: {encoded}"
            );
            assert!(
                encoded.contains("test_metrics_floor 0"),
                "expected floor 0: {encoded}"
            );
            assert!(
                encoded.contains("test_metrics_next 0"),
                "expected next 0: {encoded}"
            );

            // Append updates tip without enqueue
            (queue, _) = queue.append(vec![0]).await.unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_tip 1"),
                "expected tip 1: {encoded}"
            );
            let mut queue = queue.commit().await.unwrap();

            // Enqueue updates tip further
            for i in 1..10u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_tip 10"),
                "expected tip 10: {encoded}"
            );

            // Multiple dequeues advance next
            reader.try_recv().await.unwrap();
            reader.try_recv().await.unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_next 2"),
                "expected next 2: {encoded}"
            );

            // Sequential ack advances floor
            reader.ack(0).unwrap();
            reader.ack(1).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 2"),
                "expected floor 2: {encoded}"
            );

            // Out-of-order ack: floor stays until gap fills
            reader.ack(4).unwrap();
            reader.ack(6).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 2"),
                "expected floor still 2: {encoded}"
            );

            // Fill gap coalesces floor forward
            reader.ack(2).unwrap();
            reader.ack(3).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 5"),
                "expected floor 5: {encoded}"
            );

            // ack_up_to advances floor past sparse ack at 6
            reader.ack_up_to(8).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 8"),
                "expected floor 8: {encoded}"
            );

            // Ack remaining
            reader.ack(8).unwrap();
            reader.ack(9).unwrap();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_floor 10"),
                "expected floor 10: {encoded}"
            );

            // Reset brings next back to floor
            reader.reset();
            let encoded = context.encode();
            assert!(
                encoded.contains("test_metrics_next 10"),
                "expected next 10: {encoded}"
            );
        });
    }

    #[test_traced]
    fn test_metrics_next_updates_on_fast_forward() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test-ff", &context);
            let ctx = context.child("test_ff");
            let (mut queue, mut reader) = Queue::<_, Vec<u8>>::init(ctx, cfg).await.unwrap();

            // Enqueue 3 items, dequeue and ack only the first
            for i in 0..3u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }
            let (pos, _) = reader.try_recv().await.unwrap().unwrap();
            reader.ack(pos).unwrap();

            let encoded = context.encode();
            assert!(
                encoded.contains("test_ff_next 1"),
                "expected next 1: {encoded}"
            );

            // Ack remaining items out-of-order to advance floor to 3
            reader.ack(2).unwrap();
            reader.ack(1).unwrap();
            assert_eq!(reader.ack_floor(), 3);

            // next metric is still 1 (no dequeue yet)
            let encoded = context.encode();
            assert!(
                encoded.contains("test_ff_next 1"),
                "expected next still 1: {encoded}"
            );

            // Dequeue returns None but fast-forwards read_pos to ack_floor
            assert!(reader.try_recv().await.unwrap().is_none());
            let encoded = context.encode();
            assert!(
                encoded.contains("test_ff_next 3"),
                "expected next 3 after fast-forward: {encoded}"
            );
        });
    }

    /// An enqueued item reaches the reader and can be acknowledged.
    #[test_traced]
    fn test_reader_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create independent handles for publishing, receiving, and acknowledging one item.
            let cfg = test_config("test_reader_basic", &context);
            let (queue, mut reader) = init(context, cfg).await.unwrap();

            // Enqueue from queue
            let (_queue, pos) = queue.enqueue(b"hello".to_vec()).await.unwrap();
            assert_eq!(pos, 0);

            // Receive from reader
            let (recv_pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(recv_pos, 0);
            assert_eq!(item, b"hello".to_vec());

            // Ack the item
            reader.ack(recv_pos).unwrap();
            assert!(reader.is_empty());
        });
    }

    /// Appended items reach the reader only once committed.
    #[test_traced]
    fn test_reader_append_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize separate handles to observe the publication boundary.
            let cfg = test_config("test_reader_append_commit", &context);
            let (mut queue, mut reader) = init(context, cfg).await.unwrap();

            // Append several items without committing
            for i in 0..5u8 {
                let pos;
                (queue, pos) = queue.append(vec![i]).await.unwrap();
                assert_eq!(pos, i as u64);
            }

            // The reader cannot see or acknowledge them before commit
            assert!(reader.try_recv().await.unwrap().is_none());
            assert!(matches!(
                reader.ack(0),
                Err(Error::PositionOutOfRange(0, 0))
            ));
            assert!(reader.is_empty());

            // Commit to publish
            let _queue = queue.commit().await.unwrap();

            // Every item is readable
            for i in 0..5 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
                reader.ack(pos).unwrap();
            }
            assert!(reader.is_empty());
        });
    }

    /// A bulk enqueue publishes its items, in order, with one commit.
    #[test_traced]
    fn test_reader_enqueue_bulk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize a reader that will observe the entire batch after one commit.
            let cfg = test_config("test_reader_bulk", &context);
            let (queue, mut reader) = init(context, cfg).await.unwrap();

            // Publish the batch with a single commit.
            let (_queue, range) = queue.enqueue_bulk((0..5u8).map(|i| vec![i])).await.unwrap();
            assert_eq!(range, 0..5);

            // Verify FIFO delivery and acknowledge every item in the published batch.
            for i in 0..5 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
                reader.ack(pos).unwrap();
            }
            assert!(reader.is_empty());
        });
    }

    /// Items enqueued by a queue task reach a concurrent reader in order.
    #[test_traced]
    fn test_reader_concurrent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Give concurrent producer and consumer tasks handles over the same journal.
            let cfg = test_config("test_reader_concurrent", &context);
            let (queue, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Spawn queue task
            let queue_handle = context.child("queue").spawn(|_ctx| async move {
                let mut queue = queue;
                for i in 0..10u8 {
                    (queue, _) = queue.enqueue(vec![i]).await.unwrap();
                }
                queue
            });

            // Reader receives items as they come
            let mut received = Vec::new();
            for _ in 0..10 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                received.push((pos, item.clone()));
                reader.ack(pos).unwrap();
            }

            // Verify all items received in order
            for (i, (pos, item)) in received.iter().enumerate() {
                assert_eq!(*pos, i as u64);
                assert_eq!(*item, vec![i as u8]);
            }

            let _ = queue_handle.await.unwrap();
        });
    }

    /// `recv` completes inside `select!`.
    #[test_traced]
    fn test_reader_select() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Prepare queue handles for receiving through select.
            let cfg = test_config("test_reader_select", &context);
            let (queue, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Enqueue an item
            let (_queue, _) = queue.enqueue(b"test".to_vec()).await.unwrap();

            // Receive through select alongside a branch that never completes.
            let result = select! {
                item = reader.recv() => item,
                _ = futures::future::pending::<()>() => unreachable!(),
            };

            let (pos, item) = result.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"test".to_vec());

            reader.ack(pos).unwrap();
        });
    }

    /// After the queue is dropped, the reader delivers the published items and then returns
    /// `None`.
    #[test_traced]
    fn test_reader_queue_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Initialize both handles before testing delivery after the queue is dropped.
            let cfg = test_config("test_reader_queue_dropped", &context);
            let (queue, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Enqueue items then drop queue
            let (queue, _) = queue.enqueue(b"item1".to_vec()).await.unwrap();
            let (queue, _) = queue.enqueue(b"item2".to_vec()).await.unwrap();
            drop(queue);

            // Reader should still get existing items
            let (pos1, _) = reader.recv().await.unwrap().unwrap();
            reader.ack(pos1).unwrap();

            let (pos2, _) = reader.recv().await.unwrap().unwrap();
            reader.ack(pos2).unwrap();

            // Next recv should return None (queue dropped, queue empty)
            let result = reader.recv().await.unwrap();
            assert!(result.is_none());
        });
    }

    /// `try_recv` returns `None` until an item is published, then returns the item.
    #[test_traced]
    fn test_reader_try_recv() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Start with an empty published view for nonblocking receive checks.
            let cfg = test_config("test_reader_try_recv", &context);
            let (queue, mut reader) = init(context, cfg).await.unwrap();

            // try_recv on empty queue returns None
            let result = reader.try_recv().await.unwrap();
            assert!(result.is_none());

            // Enqueue and try_recv
            let (_queue, _) = queue.enqueue(b"item".to_vec()).await.unwrap();
            let (pos, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"item".to_vec());

            reader.ack(pos).unwrap();
        });
    }

    /// `try_recv` alone drains every published item after the queue is dropped.
    #[test_traced]
    fn test_reader_try_recv_after_queue_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Publish items and drop the queue before any read.
            let cfg = test_config("test_reader_try_recv_dropped", &context);
            let (queue, mut reader) = init(context, cfg).await.unwrap();
            let (queue, _) = queue.enqueue_bulk((0..3u8).map(|i| vec![i])).await.unwrap();
            drop(queue);

            // The closed channel still holds the final snapshot.
            for i in 0..3 {
                let (pos, item) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
            }
            assert!(reader.try_recv().await.unwrap().is_none());
        });
    }

    /// A queue mutation dropped mid-flight destroys the queue. The reader delivers every
    /// published item, then reports the end of the queue.
    #[test_traced]
    fn test_reader_ends_after_interrupted_mutation() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Wrap storage so a queue operation can be parked during its durability barrier.
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config("test_reader_interrupted", &context);
            let (queue, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Let started syncs complete so the first enqueue publishes.
            pending.unblock();
            let (queue, _) = queue.enqueue(b"first".to_vec()).await.unwrap();

            // Park the next enqueue's durable commit, then drop it mid-flight.
            pending.arm();
            let mut enqueue = Box::pin(queue.enqueue(b"second".to_vec()));
            assert!(futures::poll!(enqueue.as_mut()).is_pending());
            drop(enqueue);

            // The reader delivers the published item, then returns None.
            let (pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"first".to_vec());
            assert!(reader.recv().await.unwrap().is_none());
        });
    }

    /// `Queue::sync` publishes appended items, like a commit.
    #[test_traced]
    fn test_reader_sync_publishes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_reader_sync_publishes", &context);
            let (queue, mut reader) = init(context, cfg).await.unwrap();

            // An appended item stays unpublished until the sync.
            let (queue, _) = queue.append(vec![7]).await.unwrap();
            assert!(reader.try_recv().await.unwrap().is_none());
            let _queue = queue.sync().await.unwrap();

            // The reader receives the synced item.
            let (pos, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, vec![7]);
        });
    }

    /// `Reader::ack_up_to` shares its floor with the queue, so a sync prunes below it.
    #[test_traced]
    fn test_reader_ack_up_to_prunes() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Publish three sections, then acknowledge the first 15 items without reading them.
            let cfg = test_config("test_reader_ack_up_to", &context);
            let (queue, mut reader) = init(context.child("first"), cfg.clone()).await.unwrap();
            let (queue, _) = queue
                .enqueue_bulk((0..25u8).map(|i| vec![i]))
                .await
                .unwrap();
            reader.ack_up_to(15).unwrap();
            assert_eq!(reader.ack_floor(), 15);

            // Syncing prunes whole sections below the floor.
            let queue = queue.sync().await.unwrap();
            drop(queue);
            drop(reader);

            // A restart resumes delivery at the pruning boundary.
            let (_queue, reader) = init(context.child("second"), cfg).await.unwrap();
            assert_eq!(reader.ack_floor(), 10);
        });
    }

    /// The queue prunes below the reader's ack floor on sync, the reader keeps receiving
    /// across the prune, and a restart re-delivers from the pruning boundary.
    #[test_traced]
    fn test_reader_sync_prunes_below_ack_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Populate multiple sections so acknowledgements can advance the pruning boundary.
            let cfg = test_config("test_reader_sync_prunes", &context);
            let (queue, mut reader) = init(context.child("first"), cfg.clone()).await.unwrap();
            let (queue, _) = queue
                .enqueue_bulk((0..25u8).map(|i| vec![i]))
                .await
                .unwrap();

            // Acknowledge the first 15 items, then sync. Sections hold 10 items, so the
            // journal prunes to position 10.
            for i in 0..15 {
                let (pos, _) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                reader.ack(pos).unwrap();
            }
            assert_eq!(reader.ack_floor(), 15);
            let queue = queue.sync().await.unwrap();
            assert_eq!(queue.size(), 25);

            // The reader moves to the pruned snapshot before its next read and receives the rest.
            let (pos, _) = reader.recv().await.unwrap().unwrap();
            assert_eq!(pos, 15);
            assert_eq!(reader.snapshot.bounds().start, 10);
            for i in 16..25 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
            }
            assert!(reader.try_recv().await.unwrap().is_none());
            drop(queue);
            drop(reader);

            // A restart resumes delivery at the pruning boundary.
            let (_queue, mut reader) = init(context.child("second"), cfg).await.unwrap();
            assert_eq!(reader.ack_floor(), 10);
            let (pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(pos, 10);
            assert_eq!(item, vec![10]);
        });
    }
}
