//! Exclusive writer and reader handles for a split [Queue](super::Queue).
//!
//! The [Writer] owns the queue's journal. Every commit publishes a snapshot of the committed
//! items, and the [Reader] delivers items from the newest snapshot without waiting on the
//! writer. The reader can await new items using [Reader::recv], which integrates with `select!`
//! for multiplexing with other futures.
//!
//! The reader shares its ack floor with the writer, and [Writer::sync] prunes items below it.

use super::{Error, cursor::Cursor};
use crate::{
    Context,
    journal::contiguous::{Contiguous as _, variable},
};
use commonware_codec::CodecShared;
use commonware_runtime::telemetry::metrics::{Gauge, GaugeExt as _};
use commonware_utils::channel::watch;
use std::{
    ops::Range,
    sync::{
        Arc,
        atomic::{AtomicU64, Ordering},
    },
};
use tracing::debug;

/// A published view of the committed items.
type Snapshot<E, V> = Arc<variable::Reader<'static, E, V>>;

/// Writer handle for enqueueing items.
///
/// Methods that mutate storage consume the writer and return it only on success: an error (or
/// a dropped future) destroys it. The reader then delivers every published item and returns
/// `None`.
pub struct Writer<E: Context, V: CodecShared> {
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

impl<E: Context, V: CodecShared> Writer<E, V> {
    /// Append and commit an item, returning its position. The reader can receive the item once
    /// this returns.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(self, item: V) -> Result<(Self, u64), Error> {
        let (writer, pos) = self.append(item).await?;
        let writer = writer.commit().await?;
        debug!(position = pos, "writer: enqueued item");
        Ok((writer, pos))
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
        let start = self.journal.size();
        for item in items {
            (self, _) = self.append(item).await?;
        }
        let end = self.journal.size();
        if end > start {
            self = self.commit().await?;
        }
        debug!(start, end, "writer: enqueued bulk");
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
        debug!(position = pos, "writer: appended item");
        Ok((self, pos))
    }

    /// Persist appended items as for [Queue::commit](super::Queue::commit), then publish them to
    /// the reader.
    pub async fn commit(mut self) -> Result<Self, Error> {
        self.journal = self.journal.commit().await?;
        self.publish().await
    }

    /// Persist appended items as for [Queue::sync](super::Queue::sync), prune items below the
    /// reader's ack floor, then publish the result to the reader.
    pub async fn sync(mut self) -> Result<Self, Error> {
        self.journal = self.journal.sync().await?;
        let floor = self.floor.load(Ordering::Relaxed);
        (self.journal, _) = self.journal.prune(floor).await?;
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
        let snapshot;
        (self.journal, snapshot) = self.journal.snapshot().await?;
        self.published = bounds;
        self.snapshots.send_replace(Arc::new(snapshot));
        Ok(self)
    }
}

/// Reader handle for dequeuing and acknowledging items.
///
/// The reader delivers items the writer has published. Acknowledgements are in-memory, and
/// [Writer::sync] prunes items below the ack floor.
pub struct Reader<E: Context, V: CodecShared> {
    /// The snapshot items are delivered from.
    snapshot: Snapshot<E, V>,

    /// Receives snapshots from the writer.
    snapshots: watch::Receiver<Snapshot<E, V>>,

    /// Delivery and acknowledgement state.
    cursor: Cursor,

    /// The ack floor shared with the writer.
    floor: Arc<AtomicU64>,
}

impl<E: Context, V: CodecShared> Reader<E, V> {
    /// Receive the next unacknowledged item, waiting if necessary.
    ///
    /// This method is designed for use with `select!`. It will:
    /// 1. Return immediately if an unacked item has been published
    /// 2. Wait for the writer to publish new items otherwise
    /// 3. Return `None` once the writer is dropped and every published item has been delivered
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn recv(&mut self) -> Result<Option<(u64, V)>, Error> {
        loop {
            if let Some(item) = self.try_recv().await? {
                return Ok(Some(item));
            }

            // `try_recv` has seen the newest snapshot, so wait for the next one.
            if self.snapshots.changed().await.is_err() {
                return Ok(None);
            }
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
        if let Some(item) = self.cursor.dequeue(&*self.snapshot).await? {
            return Ok(Some(item));
        }

        // Move to the newest snapshot if the writer published one.
        let newest = self.snapshots.borrow_and_update().clone();
        if Arc::ptr_eq(&newest, &self.snapshot) {
            return Ok(None);
        }
        self.snapshot = newest;
        self.cursor.dequeue(&*self.snapshot).await
    }

    /// See [Queue::ack](super::Queue::ack).
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `position` has not been published.
    pub fn ack(&mut self, position: u64) -> Result<(), Error> {
        self.cursor.ack(position, self.published())?;
        self.floor.store(self.cursor.ack_floor(), Ordering::Relaxed);
        Ok(())
    }

    /// See [Queue::ack_up_to](super::Queue::ack_up_to).
    ///
    /// # Errors
    ///
    /// Returns [Error::PositionOutOfRange] if `up_to` exceeds the published items.
    pub fn ack_up_to(&mut self, up_to: u64) -> Result<(), Error> {
        self.cursor.ack_up_to(up_to, self.published())?;
        self.floor.store(self.cursor.ack_floor(), Ordering::Relaxed);
        Ok(())
    }

    /// See [Queue::ack_floor](super::Queue::ack_floor).
    pub const fn ack_floor(&self) -> u64 {
        self.cursor.ack_floor()
    }

    /// See [Queue::read_position](super::Queue::read_position).
    pub const fn read_position(&self) -> u64 {
        self.cursor.read_position()
    }

    /// Returns whether every published item has been acknowledged.
    pub fn is_empty(&self) -> bool {
        self.cursor.is_empty(self.published())
    }

    /// See [Queue::reset](super::Queue::reset).
    pub fn reset(&mut self) {
        self.cursor.reset();
    }

    /// Returns the number of published items.
    fn published(&self) -> u64 {
        self.snapshots.borrow().bounds().end
    }
}

/// Publish an initial snapshot of `journal` and return the handles that share it.
pub(super) async fn handles<E: Context, V: CodecShared>(
    journal: variable::Journal<E, V>,
    cursor: Cursor,
    tip: Gauge,
) -> Result<(Writer<E, V>, Reader<E, V>), Error> {
    let published = journal.bounds();
    let (journal, snapshot) = journal.snapshot().await?;
    let snapshot = Arc::new(snapshot);
    let (sender, receiver) = watch::channel(snapshot.clone());
    let floor = Arc::new(AtomicU64::new(cursor.ack_floor()));

    let writer = Writer {
        journal,
        tip,
        published,
        snapshots: sender,
        floor: floor.clone(),
    };

    let reader = Reader {
        snapshot,
        snapshots: receiver,
        cursor,
        floor,
    };

    Ok((writer, reader))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::queue::{Config, Queue};
    use commonware_codec::RangeCfg;
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{
        BufferPooler, Clock, Runner, Spawner, Supervisor as _,
        buffer::paged::CacheRef,
        deterministic,
        mocks::{DelayedSyncContext, PendingSyncs},
    };
    use commonware_utils::{NZU16, NZU64, NZUsize};
    use std::num::{NonZeroU16, NonZeroUsize};

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
    ) -> Result<(Writer<E, Vec<u8>>, Reader<E, Vec<u8>>), Error> {
        Queue::init(context, cfg).await?.split().await
    }

    #[test_traced]
    fn test_split_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_basic", &context);
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            // Enqueue from writer
            let (_writer, pos) = writer.enqueue(b"hello".to_vec()).await.unwrap();
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

    /// The reader continues from the queue's read position and acknowledgements, and receives
    /// items appended before the split.
    #[test_traced]
    fn test_split_continues_from_queue() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_continues", &context);
            let mut queue = Queue::init(context, cfg).await.unwrap();

            // Deliver and acknowledge the first of two enqueued items, then append a third.
            for i in 0..2u8 {
                (queue, _) = queue.enqueue(vec![i]).await.unwrap();
            }
            let (pos, _) = queue.dequeue().await.unwrap().unwrap();
            queue.ack(pos).unwrap();
            (queue, _) = queue.append(vec![2]).await.unwrap();

            // The reader resumes after the delivered item, including the uncommitted append.
            let (_writer, mut reader) = queue.split().await.unwrap();
            assert_eq!(reader.ack_floor(), 1);
            assert_eq!(reader.read_position(), 1);
            for i in 1..3 {
                let (pos, item) = reader.try_recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
            }
            assert!(reader.try_recv().await.unwrap().is_none());
        });
    }

    /// Appended items reach the reader only once committed.
    #[test_traced]
    fn test_split_append_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_append_commit", &context);
            let (mut writer, mut reader) = init(context, cfg).await.unwrap();

            // Append several items without committing
            for i in 0..5u8 {
                let pos;
                (writer, pos) = writer.append(vec![i]).await.unwrap();
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
            let _writer = writer.commit().await.unwrap();

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

    #[test_traced]
    fn test_split_enqueue_bulk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_bulk", &context);
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            let (_writer, range) = writer
                .enqueue_bulk((0..5u8).map(|i| vec![i]))
                .await
                .unwrap();
            assert_eq!(range, 0..5);

            for i in 0..5 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
                reader.ack(pos).unwrap();
            }
            assert!(reader.is_empty());
        });
    }

    #[test_traced]
    fn test_split_concurrent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_concurrent", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Spawn writer task
            let writer_handle = context.child("writer").spawn(|_ctx| async move {
                let mut writer = writer;
                for i in 0..10u8 {
                    (writer, _) = writer.enqueue(vec![i]).await.unwrap();
                }
                writer
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

            let _ = writer_handle.await.unwrap();
        });
    }

    #[test_traced]
    fn test_split_select() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_select", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Enqueue an item
            let (_writer, _) = writer.enqueue(b"test".to_vec()).await.unwrap();

            // Use select to receive with timeout
            let result = select! {
                item = reader.recv() => item,
                _ = context.sleep(std::time::Duration::from_secs(1)) => {
                    panic!("timeout")
                },
            };

            let (pos, item) = result.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"test".to_vec());

            reader.ack(pos).unwrap();
        });
    }

    #[test_traced]
    fn test_split_writer_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_writer_dropped", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Enqueue items then drop writer
            let (writer, _) = writer.enqueue(b"item1".to_vec()).await.unwrap();
            let (writer, _) = writer.enqueue(b"item2".to_vec()).await.unwrap();
            drop(writer);

            // Reader should still get existing items
            let (pos1, _) = reader.recv().await.unwrap().unwrap();
            reader.ack(pos1).unwrap();

            let (pos2, _) = reader.recv().await.unwrap().unwrap();
            reader.ack(pos2).unwrap();

            // Next recv should return None (writer dropped, queue empty)
            let result = reader.recv().await.unwrap();
            assert!(result.is_none());
        });
    }

    #[test_traced]
    fn test_split_try_recv() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_try_recv", &context);
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            // try_recv on empty queue returns None
            let result = reader.try_recv().await.unwrap();
            assert!(result.is_none());

            // Enqueue and try_recv
            let (_writer, _) = writer.enqueue(b"item".to_vec()).await.unwrap();
            let (pos, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"item".to_vec());

            reader.ack(pos).unwrap();
        });
    }

    /// A writer mutation dropped mid-flight destroys the writer. The reader delivers every
    /// published item, then reports the end of the queue.
    #[test_traced]
    fn test_split_interrupted_writer_ends_queue() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let pending = PendingSyncs::default();
            let context = DelayedSyncContext {
                inner: context,
                pending: pending.clone(),
            };
            let cfg = test_config("test_split_interrupted", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Let started syncs complete so the first enqueue publishes.
            pending.unblock();
            let (writer, _) = writer.enqueue(b"first".to_vec()).await.unwrap();

            // Park the next enqueue's durable commit, then drop it mid-flight.
            pending.arm();
            let mut enqueue = Box::pin(writer.enqueue(b"second".to_vec()));
            assert!(futures::poll!(enqueue.as_mut()).is_pending());
            drop(enqueue);

            // The reader delivers the published item, then returns None.
            let (pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"first".to_vec());
            assert!(reader.recv().await.unwrap().is_none());
        });
    }

    /// The writer prunes below the reader's ack floor on sync, the reader keeps receiving
    /// across the prune, and a restart re-delivers from the pruning boundary.
    #[test_traced]
    fn test_split_sync_prunes_below_ack_floor() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_split_sync_prunes", &context);
            let (writer, mut reader) = init(context.child("first"), cfg.clone()).await.unwrap();
            let (writer, _) = writer
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
            let writer = writer.sync().await.unwrap();
            assert_eq!(writer.size(), 25);

            // The reader receives the rest after the prune.
            for i in 15..25 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
            }
            assert!(reader.try_recv().await.unwrap().is_none());
            drop(writer);
            drop(reader);

            // A restart re-delivers every unpruned item.
            let (_writer, mut reader) = init(context.child("second"), cfg).await.unwrap();
            assert_eq!(reader.ack_floor(), 10);
            let (pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(pos, 10);
            assert_eq!(item, vec![10]);
        });
    }
}
