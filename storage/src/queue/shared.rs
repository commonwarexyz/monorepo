//! Shared queue with split writer/reader handles.
//!
//! Provides concurrent access to a [Queue] with multiple writers and a single reader.
//! The reader can await new items using [Reader::recv], which integrates
//! with `select!` for multiplexing with other futures.
//!
//! Writers can be cloned to allow multiple tasks to enqueue items concurrently.

use super::{Config, Error, Queue};
use crate::Context;
use commonware_codec::CodecShared;
use commonware_utils::{
    channel::mpsc,
    sync::{AsyncMutex, AsyncMutexGuard},
};
use std::{ops::Range, sync::Arc};
use tracing::debug;

/// The shared queue cell.
///
/// Queue mutations take the queue by value, so shared handles keep it in an `Option`:
/// taken out for each mutation and put back on success. If a mutation fails or its future
/// is dropped mid-flight, the cell is left empty and every later call returns
/// [Error::Unavailable]; reopen the queue to recover.
type Cell<E, V> = Arc<AsyncMutex<Option<Queue<E, V>>>>;

/// Take the queue out of a locked cell, or report it lost.
fn take<E: Context, V: CodecShared>(
    guard: &mut AsyncMutexGuard<'_, Option<Queue<E, V>>>,
) -> Result<Queue<E, V>, Error> {
    guard.take().ok_or(Error::Unavailable)
}

/// Borrow the queue in a locked cell, or report it lost.
fn peek<'a, E: Context, V: CodecShared>(
    guard: &'a AsyncMutexGuard<'_, Option<Queue<E, V>>>,
) -> Result<&'a Queue<E, V>, Error> {
    guard.as_ref().ok_or(Error::Unavailable)
}

/// Mutably borrow the queue in a locked cell, or report it lost.
fn peek_mut<'a, E: Context, V: CodecShared>(
    guard: &'a mut AsyncMutexGuard<'_, Option<Queue<E, V>>>,
) -> Result<&'a mut Queue<E, V>, Error> {
    guard.as_mut().ok_or(Error::Unavailable)
}

/// Writer handle for enqueueing items.
///
/// This handle can be cloned to allow multiple tasks to enqueue items concurrently.
/// All clones share the same underlying queue and notification channel. Any method
/// returns [Error::Unavailable] if an earlier mutation failed or was interrupted;
/// reopen the queue to recover.
pub struct Writer<E: Context, V: CodecShared> {
    queue: Cell<E, V>,
    notify: mpsc::Sender<()>,
}

impl<E: Context, V: CodecShared> Clone for Writer<E, V> {
    fn clone(&self) -> Self {
        Self {
            queue: self.queue.clone(),
            notify: self.notify.clone(),
        }
    }
}

impl<E: Context, V: CodecShared> Writer<E, V> {
    /// Enqueue an item, returning its position. The lock is held for the
    /// full append + commit, so no reader can see the item until it is durable.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn enqueue(&self, item: V) -> Result<u64, Error> {
        let mut guard = self.queue.lock().await;
        let (queue, pos) = take(&mut guard)?.enqueue(item).await?;
        *guard = Some(queue);
        drop(guard);

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
        let mut guard = self.queue.lock().await;
        let mut queue = take(&mut guard)?;
        let start = queue.size();
        for item in items {
            (queue, _) = queue.append(item).await?;
        }
        let end = queue.size();
        if end > start {
            queue = queue.commit().await?;
        }
        *guard = Some(queue);
        drop(guard);

        if start < end {
            let _ = self.notify.try_send(());
        }
        debug!(start, end, "writer: enqueued bulk");
        Ok(start..end)
    }

    /// Append an item without committing, returning its position. The item
    /// is immediately visible to the reader but is **not durable** until
    /// [Self::commit] or [Self::sync] is called.
    ///
    /// # Errors
    ///
    /// Returns an error if the underlying storage operation fails.
    pub async fn append(&self, item: V) -> Result<u64, Error> {
        let mut guard = self.queue.lock().await;
        let (queue, pos) = take(&mut guard)?.append(item).await?;
        *guard = Some(queue);
        drop(guard);
        let _ = self.notify.try_send(());
        debug!(position = pos, "writer: appended item");
        Ok(pos)
    }

    /// See [Queue::commit](super::Queue::commit).
    pub async fn commit(&self) -> Result<(), Error> {
        let mut guard = self.queue.lock().await;
        let queue = take(&mut guard)?.commit().await?;
        *guard = Some(queue);
        Ok(())
    }

    /// See [Queue::sync](super::Queue::sync).
    pub async fn sync(&self) -> Result<(), Error> {
        let mut guard = self.queue.lock().await;
        let queue = take(&mut guard)?.sync().await?;
        *guard = Some(queue);
        Ok(())
    }

    /// Returns the total number of items that have been enqueued.
    pub async fn size(&self) -> Result<u64, Error> {
        Ok(peek(&self.queue.lock().await)?.size())
    }
}

/// Reader handle for dequeuing and acknowledging items.
///
/// There should only be one reader per shared queue. Any method returns
/// [Error::Unavailable] if an earlier mutation failed or was interrupted; reopen the
/// queue to recover.
pub struct Reader<E: Context, V: CodecShared> {
    queue: Cell<E, V>,
    notify: mpsc::Receiver<()>,
}

impl<E: Context, V: CodecShared> Reader<E, V> {
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
            if let Some(item) = self.dequeue().await? {
                return Ok(Some(item));
            }

            // No item available, wait for notification
            // Returns None if writer is dropped
            if self.notify.recv().await.is_none() {
                // Writer dropped, drain any remaining items
                return self.dequeue().await;
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

        self.dequeue().await
    }

    /// Dequeue through the shared cell.
    async fn dequeue(&self) -> Result<Option<(u64, V)>, Error> {
        peek_mut(&mut self.queue.lock().await)?.dequeue().await
    }

    /// See [Queue::ack].
    ///
    /// # Errors
    ///
    /// Returns [super::Error::PositionOutOfRange] if the position is invalid.
    pub async fn ack(&self, position: u64) -> Result<(), Error> {
        peek_mut(&mut self.queue.lock().await)?.ack(position)
    }

    /// See [Queue::ack_up_to].
    ///
    /// # Errors
    ///
    /// Returns [super::Error::PositionOutOfRange] if `up_to` is invalid.
    pub async fn ack_up_to(&self, up_to: u64) -> Result<(), Error> {
        peek_mut(&mut self.queue.lock().await)?.ack_up_to(up_to)
    }

    /// See [Queue::ack_floor].
    pub async fn ack_floor(&self) -> Result<u64, Error> {
        Ok(peek(&self.queue.lock().await)?.ack_floor())
    }

    /// See [Queue::read_position].
    pub async fn read_position(&self) -> Result<u64, Error> {
        Ok(peek(&self.queue.lock().await)?.read_position())
    }

    /// See [Queue::is_empty].
    pub async fn is_empty(&self) -> Result<bool, Error> {
        Ok(peek(&self.queue.lock().await)?.is_empty())
    }

    /// See [Queue::reset].
    pub async fn reset(&self) -> Result<(), Error> {
        peek_mut(&mut self.queue.lock().await)?.reset();
        Ok(())
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
pub async fn init<E: Context, V: CodecShared>(
    context: E,
    cfg: Config<V::Cfg>,
) -> Result<(Writer<E, V>, Reader<E, V>), Error> {
    let queue = Arc::new(AsyncMutex::new(Some(Queue::init(context, cfg).await?)));
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
    use commonware_runtime::{
        BufferPooler, Clock, Runner, Spawner, Supervisor as _, buffer::paged::CacheRef,
        deterministic,
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
        }
    }

    #[test_traced]
    fn test_shared_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_basic", &context);
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
            assert!(reader.is_empty().await.unwrap());
        });
    }

    #[test_traced]
    fn test_shared_append_commit() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_append_commit", &context);
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
            assert!(reader.is_empty().await.unwrap());
        });
    }

    #[test_traced]
    fn test_shared_enqueue_bulk() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_bulk", &context);
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
            assert!(reader.is_empty().await.unwrap());
        });
    }

    #[test_traced]
    fn test_shared_concurrent() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_concurrent", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Spawn writer task
            let writer_handle = context.child("writer").spawn(|_ctx| async move {
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
            let cfg = test_config("test_shared_select", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

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
            let cfg = test_config("test_shared_writer_dropped", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

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
            let _ = Arc::try_unwrap(queue)
                .unwrap_or_else(|_| panic!("queue should have a single reference"))
                .into_inner();
        });
    }

    #[test_traced]
    fn test_shared_try_recv() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            let cfg = test_config("test_shared_try_recv", &context);
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
            let cfg = test_config("test_shared_multi_writer", &context);
            let (writer, mut reader) = init(context.child("storage"), cfg).await.unwrap();

            // Clone writer for second task
            let writer2 = writer.clone();

            // Spawn two writer tasks
            let handle1 =
                context
                    .child("writer")
                    .with_attribute("index", 1)
                    .spawn(|_ctx| async move {
                        for i in 0..5u8 {
                            writer.enqueue(vec![i]).await.unwrap();
                        }
                        writer
                    });

            let handle2 =
                context
                    .child("writer")
                    .with_attribute("index", 2)
                    .spawn(|_ctx| async move {
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
