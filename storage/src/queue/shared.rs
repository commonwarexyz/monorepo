//! Shared queue with split writer/reader handles.
//!
//! Provides concurrent access to a [Queue] with multiple writers and a single reader.
//! The reader can await new items using [Reader::recv], which integrates
//! with `select!` for multiplexing with other futures.
//!
//! Writers can be cloned to allow multiple tasks to enqueue items concurrently.

use super::{Config, Error, Queue};
use crate::Persistable;
use commonware_codec::CodecShared;
use commonware_runtime::{Clock, Metrics, Storage};
use commonware_utils::channel::mpsc;
use futures::lock::Mutex;
use std::{ops::Range, sync::Arc};
use tracing::debug;

/// Writer handle for enqueueing items.
///
/// This handle can be cloned to allow multiple tasks to enqueue items concurrently.
/// All clones share the same underlying queue and notification channel.
pub struct Writer<E: Clock + Storage + Metrics, V: CodecShared> {
    queue: Arc<Mutex<Queue<E, V>>>,
    notify: mpsc::Sender<()>,
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Clone for Writer<E, V> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Writer<E, V> {
    /// Enqueue an item, returning its position. The lock is held for the
    /// full append + commit, so no reader can see the item until it is durable.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(&self, item: V) -> Result<u64, Error> {
        let pos = self.queue.lock().await.enqueue(item).await?;

        // Fire-and-forget so the writer never blocks on reader wake-up.
        // The reader always checks the queue under lock, so a missed
        // notification never causes a missed item.
        let _ = self.notify.try_send(());

        debug!(position = pos, "writer: enqueued item");
        Ok(pos)
    }

    /// Enqueue a batch of items with a single commit, returning positions
    /// `[start, end)`. The lock is held for the full batch, so no reader can
    /// see any item until the entire batch is durable.
    ///
    /// # Errors
    ///
    /// Returns an error if any append or the final commit fails.
    pub async fn enqueue_bulk(
        &self,
        items: impl IntoIterator<Item = V>,
    ) -> Result<Range<u64>, Error> {
        let mut queue = self.queue.lock().await;
        let start = queue.size().await;
        for item in items {
            queue.append(item).await?;
        }
        let end = queue.size().await;
        if end > start {
            queue.commit().await?;
        }
        drop(queue);

        if start < end {
            let _ = self.notify.try_send(());
        }
        debug!(start, end, "writer: enqueued bulk");
        Ok(start..end)
    }

    /// Append an item without committing, returning its position. The item
    /// is immediately visible to the reader but is **not durable** until
    /// [Self::commit] is called or the underlying journal auto-syncs at a
    /// section boundary (see [`variable::Journal`](crate::journal::contiguous::variable::Journal)
    /// invariant 1).
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn append(&self, item: V) -> Result<u64, Error> {
        let pos = self.queue.lock().await.append(item).await?;
        let _ = self.notify.try_send(());
        debug!(position = pos, "writer: appended item");
        Ok(pos)
    }

    /// See [Queue::commit](super::Queue::commit).
    pub async fn commit(&self) -> Result<(), Error> {
        self.queue.lock().await.commit().await
    }

    /// See [Queue::sync](super::Queue::sync).
    pub async fn sync(&self) -> Result<(), Error> {
        self.queue.lock().await.sync().await
    }

    /// Returns the total number of items that have been enqueued.
    pub async fn size(&self) -> u64 {
        self.queue.lock().await.size().await
    }
}

/// Reader handle for dequeuing and acknowledging items.
///
/// There should only be one reader per shared queue.
pub struct Reader<E: Clock + Storage + Metrics, V: CodecShared> {
    queue: Arc<Mutex<Queue<E, V>>>,
    notify: mpsc::Receiver<()>,
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Reader<E, V> {
    /// Receive the next unacknowledged item, waiting if necessary.
    ///
    /// This method is designed for use with `select!`. It will:
    /// 1. Return immediately if an unacked item is available
    /// 2. Wait for the writer to enqueue new items if the queue is empty
    /// 3. Return `None` if the writer is dropped (no more items will arrive)
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn recv(&mut self) -> Result<Option<(u64, V)>, Error> {
        loop {
            // Try to dequeue an item
            if let Some(item) = self.queue.lock().await.dequeue().await? {
                return Ok(Some(item));
            }

            // No item available, wait for notification
            // Returns None if writer is dropped
            if self.notify.recv().await.is_none() {
                // Writer dropped, drain any remaining items
                return self.queue.lock().await.dequeue().await;
            }
        }
    }

    /// Try to dequeue the next unacknowledged item without waiting.
    ///
    /// Returns `None` immediately if no unacked item is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn try_recv(&mut self) -> Result<Option<(u64, V)>, Error> {
        // Drain pending notification (capacity is 1, so at most 1 buffered).
        let _ = self.notify.try_recv();

        self.queue.lock().await.dequeue().await
    }

    /// See [Queue::ack].
    ///
    /// # Errors
    ///
    /// Returns [super::Error::PositionOutOfRange] if the position is invalid.
    pub async fn ack(&self, position: u64) -> Result<(), Error> {
        self.queue.lock().await.ack(position).await
    }

    /// See [Queue::ack_up_to].
    ///
    /// # Errors
    ///
    /// Returns [super::Error::PositionOutOfRange] if `up_to` is invalid.
    pub async fn ack_up_to(&self, up_to: u64) -> Result<(), Error> {
        self.queue.lock().await.ack_up_to(up_to).await
    }

    /// See [Queue::ack_floor].
    pub async fn ack_floor(&self) -> u64 {
        self.queue.lock().await.ack_floor()
    }

    /// See [Queue::read_position].
    pub async fn read_position(&self) -> u64 {
        self.queue.lock().await.read_position()
    }

    /// See [Queue::is_empty].
    pub async fn is_empty(&self) -> bool {
        self.queue.lock().await.is_empty().await
    }

    /// See [Queue::reset].
    pub async fn reset(&self) {
        self.queue.lock().await.reset();
    }
}

/// Initialize a shared queue and split into writer and reader handles.
///
/// # Example
///
/// ```rust,ignore
/// use commonware_macros::select;
///
/// let (writer, mut reader) = shared::init(context, config).await?;
///
/// // Writer task (clone for multiple producers)
/// writer.enqueue(item).await?;
///
/// // Reader task
/// loop {
///     select! {
///         result = reader.recv() => {
///             let Some((pos, item)) = result? else { break };
///             // Process item...
///             reader.ack(pos).await?;
///         }
///         _ = shutdown => break,
///     }
/// }
/// ```
pub async fn init<E: Clock + Storage + Metrics, V: CodecShared>(
    context: E,
    cfg: Config<V::Cfg>,
) -> Result<(Writer<E, V>, Reader<E, V>), Error> {
    let queue = Arc::new(Mutex::new(Queue::init(context, cfg).await?));
    let (notify_tx, notify_rx) = mpsc::channel(1);

    let writer = Writer {
        queue: queue.clone(),
        notify: notify_tx,
    };

    let reader = Reader {
        queue,
        notify: notify_rx,
    };

    Ok((writer, reader))
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::RangeCfg;
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Spawner};
    use commonware_utils::{NZUsize, NZU16, NZU64};
    use std::num::{NonZeroU16, NonZeroUsize};

    const PAGE_SIZE: NonZeroU16 = NZU16!(1024);
    const PAGE_CACHE_SIZE: NonZeroUsize = NZUsize!(10);

    fn test_config(partition: &str) -> Config<(RangeCfg<usize>, ())> {
        Config {
            partition: partition.to_string(),
            items_per_section: NZU64!(10),
            compression: None,
            codec_config: ((0..).into(), ()),
            page_cache: CacheRef::new(PAGE_SIZE, PAGE_CACHE_SIZE),
            write_buffer: NZUsize!(4096),
        }
    }

    #[test_traced]
    fn test_shared_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_basic");
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            // Enqueue from writer
            let pos = writer.enqueue(b"hello".to_vec()).await.unwrap();
            assert_eq!(pos, 0);

            // Receive from reader
            let (recv_pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(recv_pos, 0);
            assert_eq!(item, b"hello".to_vec());

            // Ack the item
            reader.ack(recv_pos).await.unwrap();
            assert!(reader.is_empty().await);
        });
    }

    #[test_traced]
    fn test_shared_append_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_append_commit");
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            // Append several items without committing
            for i in 0..5u8 {
                let pos = writer.append(vec![i]).await.unwrap();
                assert_eq!(pos, i as u64);
            }

            // Reader can see them before commit
            let (pos, item) = reader.recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, vec![0]);

            // Commit to make durable
            writer.commit().await.unwrap();

            // Remaining items still readable
            for i in 1..5 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
                reader.ack(pos).await.unwrap();
            }

            reader.ack(0).await.unwrap();
            assert!(reader.is_empty().await);
        });
    }

    #[test_traced]
    fn test_shared_enqueue_bulk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_bulk");
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            let range = writer
                .enqueue_bulk((0..5u8).map(|i| vec![i]))
                .await
                .unwrap();
            assert_eq!(range, 0..5);

            for i in 0..5 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                assert_eq!(pos, i);
                assert_eq!(item, vec![i as u8]);
                reader.ack(pos).await.unwrap();
            }
            assert!(reader.is_empty().await);
        });
    }

    #[test_traced]
    fn test_shared_concurrent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_concurrent");
            let (writer, mut reader) = init(context.clone(), cfg).await.unwrap();

            // Spawn writer task
            let writer_handle = context.with_label("writer").spawn(|_ctx| async move {
                for i in 0..10u8 {
                    writer.enqueue(vec![i]).await.unwrap();
                }
                writer
            });

            // Reader receives items as they come
            let mut received = Vec::new();
            for _ in 0..10 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                received.push((pos, item.clone()));
                reader.ack(pos).await.unwrap();
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
    fn test_shared_select() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_select");
            let (writer, mut reader) = init(context.clone(), cfg).await.unwrap();

            // Enqueue an item
            writer.enqueue(b"test".to_vec()).await.unwrap();

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

            reader.ack(pos).await.unwrap();
        });
    }

    #[test_traced]
    fn test_shared_writer_dropped() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_writer_dropped");
            let (writer, mut reader) = init(context.clone(), cfg).await.unwrap();

            // Enqueue items then drop writer
            writer.enqueue(b"item1".to_vec()).await.unwrap();
            writer.enqueue(b"item2".to_vec()).await.unwrap();

            // Get the queue before dropping writer
            let queue = writer.queue.clone();
            drop(writer);

            // Reader should still get existing items
            let (pos1, _) = reader.recv().await.unwrap().unwrap();
            reader.ack(pos1).await.unwrap();

            let (pos2, _) = reader.recv().await.unwrap().unwrap();
            reader.ack(pos2).await.unwrap();

            // Next recv should return None (writer dropped, queue empty)
            let result = reader.recv().await.unwrap();
            assert!(result.is_none());

            drop(reader);
            let _ = Arc::try_unwrap(queue).unwrap().into_inner();
        });
    }

    #[test_traced]
    fn test_shared_try_recv() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_try_recv");
            let (writer, mut reader) = init(context, cfg).await.unwrap();

            // try_recv on empty queue returns None
            let result = reader.try_recv().await.unwrap();
            assert!(result.is_none());

            // Enqueue and try_recv
            writer.enqueue(b"item".to_vec()).await.unwrap();
            let (pos, item) = reader.try_recv().await.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"item".to_vec());

            reader.ack(pos).await.unwrap();
        });
    }

    #[test_traced]
    fn test_shared_multiple_writers() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_multi_writer");
            let (writer, mut reader) = init(context.clone(), cfg).await.unwrap();

            // Clone writer for second task
            let writer2 = writer.clone();

            // Spawn two writer tasks
            let handle1 = context.with_label("writer1").spawn(|_ctx| async move {
                for i in 0..5u8 {
                    writer.enqueue(vec![i]).await.unwrap();
                }
                writer
            });

            let handle2 = context.with_label("writer2").spawn(|_ctx| async move {
                for i in 5..10u8 {
                    writer2.enqueue(vec![i]).await.unwrap();
                }
            });

            // Reader receives all 10 items
            let mut received = Vec::new();
            for _ in 0..10 {
                let (pos, item) = reader.recv().await.unwrap().unwrap();
                received.push(item[0]);
                reader.ack(pos).await.unwrap();
            }

            // All items should be received (order may vary due to concurrent writes)
            received.sort();
            assert_eq!(received, (0..10u8).collect::<Vec<_>>());

            let _ = handle1.await.unwrap();
            handle2.await.unwrap();
        });
    }
}
