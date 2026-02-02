//! Shared queue with split writer/reader handles.
//!
//! Provides concurrent access to a [Queue] with multiple writers and a single reader.
//! The reader can await new items using [QueueReader::recv], which integrates
//! with `select!` for multiplexing with other futures.
//!
//! Writers can be cloned to allow multiple tasks to enqueue items concurrently.

use super::{Config, Error, Queue};
use crate::Persistable;
use commonware_codec::CodecShared;
use commonware_runtime::{Clock, Metrics, Storage};
use futures::channel::mpsc;
use futures::lock::Mutex;
use futures::StreamExt;
use std::sync::Arc;
use tracing::debug;

/// Writer handle for enqueueing items.
///
/// This handle can be cloned to allow multiple tasks to enqueue items concurrently.
/// All clones share the same underlying queue and notification channel.
pub struct QueueWriter<E: Clock + Storage + Metrics, V: CodecShared> {
    queue: Arc<Mutex<Queue<E, V>>>,
    notify: Arc<Mutex<mpsc::Sender<()>>>,
}

impl<E: Clock + Storage + Metrics, V: CodecShared> Clone for QueueWriter<E, V> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<E: Clock + Storage + Metrics, V: CodecShared> QueueWriter<E, V> {
    /// Enqueue an item, returning its position.
    ///
    /// The item is durably persisted before returning. The reader will be
    /// notified that a new item is available.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(&self, item: V) -> Result<u64, Error> {
        let pos = self.queue.lock().await.enqueue(item).await?;

        // Notify reader (ignore errors: full means already notified, disconnected means reader dropped)
        let _ = self.notify.lock().await.try_send(());

        debug!(position = pos, "writer: enqueued item");
        Ok(pos)
    }

    /// Returns the total number of items that have been enqueued.
    pub async fn size(&self) -> u64 {
        self.queue.lock().await.size()
    }

    /// Checkpoint ack state to storage.
    ///
    /// See [Persistable::sync] for details.
    pub async fn sync(&self) -> Result<(), Error> {
        self.queue.lock().await.sync().await
    }
}

/// Reader handle for dequeuing and acknowledging items.
///
/// There should only be one reader per shared queue.
pub struct QueueReader<E: Clock + Storage + Metrics, V: CodecShared> {
    queue: Arc<Mutex<Queue<E, V>>>,
    notify: mpsc::Receiver<()>,
}

impl<E: Clock + Storage + Metrics, V: CodecShared> QueueReader<E, V> {
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
            if self.notify.next().await.is_none() {
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
        // Drain any pending notifications (stop if channel empty or closed)
        while let Ok(Some(_)) = self.notify.try_next() {}

        self.queue.lock().await.dequeue().await
    }

    /// Acknowledge processing of an item at the given position.
    ///
    /// See [Queue::ack] for details.
    ///
    /// # Errors
    ///
    /// Returns an error if the position is out of range or storage fails.
    pub async fn ack(&self, position: u64) -> Result<(), Error> {
        self.queue.lock().await.ack(position).await
    }

    /// Acknowledge all items up to (but not including) the given position.
    ///
    /// See [Queue::ack_up_to] for details.
    ///
    /// # Errors
    ///
    /// Returns an error if the position is out of range or storage fails.
    pub async fn ack_up_to(&self, up_to: u64) -> Result<(), Error> {
        self.queue.lock().await.ack_up_to(up_to).await
    }

    /// Peek at the next unacknowledged item without advancing the read position.
    ///
    /// See [Queue::peek] for details.
    pub async fn peek(&self) -> Result<Option<(u64, V)>, Error> {
        self.queue.lock().await.peek().await
    }

    /// Returns the current ack floor.
    pub async fn ack_floor(&self) -> u64 {
        self.queue.lock().await.ack_floor()
    }

    /// Returns the current read position.
    pub async fn read_position(&self) -> u64 {
        self.queue.lock().await.read_position()
    }

    /// Returns whether all enqueued items have been acknowledged.
    pub async fn is_empty(&self) -> bool {
        self.queue.lock().await.is_empty()
    }

    /// Reset the read position to re-deliver all unacknowledged items.
    pub async fn reset(&self) {
        self.queue.lock().await.reset();
    }

    /// Checkpoint ack state to storage.
    ///
    /// See [Persistable::sync] for details.
    pub async fn sync(&self) -> Result<(), Error> {
        self.queue.lock().await.sync().await
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
) -> Result<(QueueWriter<E, V>, QueueReader<E, V>), Error> {
    let queue = Arc::new(Mutex::new(Queue::init(context, cfg).await?));
    let (notify_tx, notify_rx) = mpsc::channel(1);

    let writer = QueueWriter {
        queue: queue.clone(),
        notify: Arc::new(Mutex::new(notify_tx)),
    };

    let reader = QueueReader {
        queue,
        notify: notify_rx,
    };

    Ok((writer, reader))
}

/// Destroy a shared queue, removing all data from storage.
///
/// Both writer and reader must be passed to ensure exclusive access.
///
/// # Panics
///
/// Panics if there are still outstanding references to the shared state
/// (which shouldn't happen if both handles are passed).
pub async fn destroy<E: Clock + Storage + Metrics, V: CodecShared>(
    writer: QueueWriter<E, V>,
    reader: QueueReader<E, V>,
) -> Result<(), Error> {
    // Drop reader first to close the channel
    drop(reader);

    // Extract the queue from the Arc<Mutex<...>>
    // This will succeed since we have both handles
    let queue = Arc::try_unwrap(writer.queue).expect("shared queue still has references");
    queue.into_inner().destroy().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_codec::RangeCfg;
    use commonware_macros::{select, test_traced};
    use commonware_runtime::{buffer::paged::CacheRef, deterministic, Runner, Spawner};
    use commonware_utils::{NZU16, NZU64, NZUsize};
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

            destroy(writer, reader).await.unwrap();
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

            let writer = writer_handle.await.unwrap();
            destroy(writer, reader).await.unwrap();
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
                }
            };

            let (pos, item) = result.unwrap().unwrap();
            assert_eq!(pos, 0);
            assert_eq!(item, b"test".to_vec());

            reader.ack(pos).await.unwrap();
            destroy(writer, reader).await.unwrap();
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

            // Clean up manually since we dropped writer
            drop(reader);
            Arc::try_unwrap(queue).unwrap().into_inner().destroy().await.unwrap();
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
            destroy(writer, reader).await.unwrap();
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

            let writer = handle1.await.unwrap();
            handle2.await.unwrap();
            destroy(writer, reader).await.unwrap();
        });
    }
}
