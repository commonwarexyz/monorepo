//! Utility functions for interacting with any runtime.

#[cfg(test)]
use crate::Runner;
use crate::{Blob, Error, Metrics, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{
    channel::oneshot,
    future::Shared,
    stream::{AbortHandle, Abortable},
    FutureExt,
};
use prometheus_client::metrics::gauge::Gauge;
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::{
    any::Any,
    future::Future,
    panic::{catch_unwind, resume_unwind, AssertUnwindSafe},
    pin::Pin,
    sync::{Arc, Once},
    task::{Context, Poll},
};
use tracing::error;

/// Yield control back to the runtime.
pub async fn reschedule() {
    struct Reschedule {
        yielded: bool,
    }

    impl Future for Reschedule {
        type Output = ();

        fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<()> {
            if self.yielded {
                Poll::Ready(())
            } else {
                self.yielded = true;
                cx.waker().wake_by_ref();
                Poll::Pending
            }
        }
    }

    Reschedule { yielded: false }.await
}

fn extract_panic_message(err: &(dyn Any + Send)) -> String {
    if let Some(s) = err.downcast_ref::<&str>() {
        s.to_string()
    } else if let Some(s) = err.downcast_ref::<String>() {
        s.clone()
    } else {
        format!("{:?}", err)
    }
}

/// Handle to a spawned task.
pub struct Handle<T>
where
    T: Send + 'static,
{
    aborter: Option<AbortHandle>,
    receiver: oneshot::Receiver<Result<T, Error>>,

    running: Gauge,
    once: Arc<Once>,
}

impl<T> Handle<T>
where
    T: Send + 'static,
{
    pub(crate) fn init<F>(
        f: F,
        running: Gauge,
        catch_panic: bool,
    ) -> (impl Future<Output = ()>, Self)
    where
        F: Future<Output = T> + Send + 'static,
    {
        // Increment running counter
        running.inc();

        // Initialize channels to handle result/abort
        let once = Arc::new(Once::new());
        let (sender, receiver) = oneshot::channel();
        let (aborter, abort_registration) = AbortHandle::new_pair();

        // Wrap the future to handle panics
        let wrapped = {
            let once = once.clone();
            let running = running.clone();
            async move {
                // Run future
                let result = AssertUnwindSafe(f).catch_unwind().await;

                // Decrement running counter
                once.call_once(|| {
                    running.dec();
                });

                // Handle result
                let result = match result {
                    Ok(result) => Ok(result),
                    Err(err) => {
                        if !catch_panic {
                            resume_unwind(err);
                        }
                        let err = extract_panic_message(&*err);
                        error!(?err, "task panicked");
                        Err(Error::Exited)
                    }
                };
                let _ = sender.send(result);
            }
        };

        // Make the future abortable
        let abortable = Abortable::new(wrapped, abort_registration);
        (
            abortable.map(|_| ()),
            Self {
                aborter: Some(aborter),
                receiver,

                running,
                once,
            },
        )
    }

    pub(crate) fn init_blocking<F>(f: F, running: Gauge, catch_panic: bool) -> (impl FnOnce(), Self)
    where
        F: FnOnce() -> T + Send + 'static,
    {
        // Increment the running tasks gauge
        running.inc();

        // Initialize channel to handle result
        let once = Arc::new(Once::new());
        let (sender, receiver) = oneshot::channel();

        // Wrap the closure with panic handling
        let f = {
            let once = once.clone();
            let running = running.clone();
            move || {
                // Run blocking task
                let result = catch_unwind(AssertUnwindSafe(f));

                // Decrement running counter
                once.call_once(|| {
                    running.dec();
                });

                // Handle result
                let result = match result {
                    Ok(value) => Ok(value),
                    Err(err) => {
                        if !catch_panic {
                            resume_unwind(err);
                        }
                        let err = extract_panic_message(&*err);
                        error!(?err, "blocking task panicked");
                        Err(Error::Exited)
                    }
                };
                let _ = sender.send(result);
            }
        };

        // Return the task and handle
        (
            f,
            Self {
                aborter: None,
                receiver,

                running,
                once,
            },
        )
    }

    /// Abort the task (if not blocking).
    pub fn abort(&self) {
        // Get aborter and abort
        let Some(aborter) = &self.aborter else {
            return;
        };
        aborter.abort();

        // Decrement running counter
        self.once.call_once(|| {
            self.running.dec();
        });
    }
}

impl<T> Future for Handle<T>
where
    T: Send + 'static,
{
    type Output = Result<T, Error>;

    fn poll(mut self: Pin<&mut Self>, cx: &mut Context<'_>) -> Poll<Self::Output> {
        match Pin::new(&mut self.receiver).poll(cx) {
            Poll::Ready(Ok(Ok(value))) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Ok(value))
            }
            Poll::Ready(Ok(Err(err))) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Err(err))
            }
            Poll::Ready(Err(_)) => {
                self.once.call_once(|| {
                    self.running.dec();
                });
                Poll::Ready(Err(Error::Closed))
            }
            Poll::Pending => Poll::Pending,
        }
    }
}

/// A one-time broadcast that can be awaited by many tasks. It is often used for
/// coordinating shutdown across many tasks.
///
/// To minimize the overhead of tracking outstanding signals (which only return once),
/// it is recommended to wait on a reference to it (i.e. `&mut signal`) instead of
/// cloning it multiple times in a given task (i.e. in each iteration of a loop).
pub type Signal = Shared<oneshot::Receiver<i32>>;

/// Coordinates a one-time signal across many tasks.
///
/// # Example
///
/// ## Basic Usage
///
/// ```rust
/// use commonware_runtime::{Spawner, Runner, Signaler, deterministic};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Setup signaler and get future
///     let (mut signaler, signal) = Signaler::new();
///
///     // Signal shutdown
///     signaler.signal(2);
///
///     // Wait for shutdown in task
///     let sig = signal.await.unwrap();
///     println!("Received signal: {}", sig);
/// });
/// ```
///
/// ## Advanced Usage
///
/// While `Futures::Shared` is efficient, there is still meaningful overhead
/// to cloning it (i.e. in each iteration of a loop). To avoid
/// a performance regression from introducing `Signaler`, it is recommended
/// to wait on a reference to `Signal` (i.e. `&mut signal`).
///
/// ```rust
/// use commonware_macros::select;
/// use commonware_runtime::{Clock, Spawner, Runner, Signaler, deterministic, Metrics};
/// use futures::channel::oneshot;
/// use std::time::Duration;
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Setup signaler and get future
///     let (mut signaler, mut signal) = Signaler::new();
///
///     // Loop on the signal until resolved
///     let (tx, rx) = oneshot::channel();
///     context.with_label("waiter").spawn(|context| async move {
///         loop {
///             // Wait for signal or sleep
///             select! {
///                  sig = &mut signal => {
///                      println!("Received signal: {}", sig.unwrap());
///                      break;
///                  },
///                  _ = context.sleep(Duration::from_secs(1)) => {},
///             };
///         }
///         let _ = tx.send(());
///     });
///
///     // Send signal
///     signaler.signal(9);
///
///     // Wait for task
///     rx.await.expect("shutdown signaled");
/// });
/// ```
pub struct Signaler {
    tx: Option<oneshot::Sender<i32>>,
}

impl Signaler {
    /// Create a new `Signaler`.
    ///
    /// Returns a `Signaler` and a `Signal` that will resolve when `signal` is called.
    pub fn new() -> (Self, Signal) {
        let (tx, rx) = oneshot::channel();
        (Self { tx: Some(tx) }, rx.shared())
    }

    /// Resolve the `Signal` for all waiters (if not already resolved).
    pub fn signal(&mut self, value: i32) {
        if let Some(stop_tx) = self.tx.take() {
            let _ = stop_tx.send(value);
        }
    }
}

/// Creates a [rayon]-compatible thread pool with [Spawner::spawn_blocking].
///
/// # Arguments
/// - `context`: The runtime context implementing the [Spawner] trait.
/// - `concurrency`: The number of tasks to execute concurrently in the pool.
///
/// # Returns
/// A `Result` containing the configured [rayon::ThreadPool] or a [rayon::ThreadPoolBuildError] if the pool cannot be built.
pub fn create_pool<S: Spawner + Metrics>(
    context: S,
    concurrency: usize,
) -> Result<ThreadPool, ThreadPoolBuildError> {
    ThreadPoolBuilder::new()
        .num_threads(concurrency)
        .spawn_handler(move |thread| {
            context
                .with_label("rayon-thread")
                .spawn_blocking(move || thread.run());
            Ok(())
        })
        .build()
}

/// Async reader–writer lock.
///
/// Powered by [async_lock::RwLock], `RwLock` provides both fair writer acquisition
/// and `try_read` / `try_write` without waiting (without any runtime-specific dependencies).
///
/// Usage:
/// ```rust
/// use commonware_runtime::{Spawner, Runner, Signaler, deterministic, RwLock};
///
/// let executor = deterministic::Runner::default();
/// executor.start(|context| async move {
///     // Create a new RwLock
///     let lock = RwLock::new(2);
///
///     // many concurrent readers
///     let r1 = lock.read().await;
///     let r2 = lock.read().await;
///     assert_eq!(*r1 + *r2, 4);
///
///     // exclusive writer
///     drop((r1, r2));
///     let mut w = lock.write().await;
///     *w += 1;
/// });
/// ```
pub struct RwLock<T>(async_lock::RwLock<T>);

/// Shared guard returned by [RwLock::read].
pub type RwLockReadGuard<'a, T> = async_lock::RwLockReadGuard<'a, T>;

/// Exclusive guard returned by [RwLock::write].
pub type RwLockWriteGuard<'a, T> = async_lock::RwLockWriteGuard<'a, T>;

impl<T> RwLock<T> {
    /// Create a new lock.
    #[inline]
    pub const fn new(value: T) -> Self {
        Self(async_lock::RwLock::new(value))
    }

    /// Acquire a shared read guard.
    #[inline]
    pub async fn read(&self) -> RwLockReadGuard<'_, T> {
        self.0.read().await
    }

    /// Acquire an exclusive write guard.
    #[inline]
    pub async fn write(&self) -> RwLockWriteGuard<'_, T> {
        self.0.write().await
    }

    /// Try to get a read guard without waiting.
    #[inline]
    pub fn try_read(&self) -> Option<RwLockReadGuard<'_, T>> {
        self.0.try_read()
    }

    /// Try to get a write guard without waiting.
    #[inline]
    pub fn try_write(&self) -> Option<RwLockWriteGuard<'_, T>> {
        self.0.try_write()
    }

    /// Get mutable access without locking (requires `&mut self`).
    #[inline]
    pub fn get_mut(&mut self) -> &mut T {
        self.0.get_mut()
    }

    /// Consume the lock, returning the inner value.
    #[inline]
    pub fn into_inner(self) -> T {
        self.0.into_inner()
    }
}

/// A reader that buffers content from a [Blob] to optimize the performance
/// of a full scan of contents.
pub struct Buffer<B: Blob> {
    /// The underlying blob to read from.
    pub blob: B,
    /// The buffer storing the data read from the blob.
    buffer: Vec<u8>,
    /// The current position in the blob from where the buffer was filled.
    pub blob_position: u64,
    /// The size of the blob.
    blob_size: u64,
    /// The current position within the buffer for reading.
    pub buffer_position: usize,
    /// The valid data length in the buffer.
    pub buffer_valid_len: usize,
    /// The maximum size of the buffer.
    buffer_size: usize,
}

impl<B: Blob> Buffer<B> {
    /// Creates a new `Buffer` that reads from the given blob with the specified buffer size.
    ///
    /// # Panics
    ///
    /// Panics if `lookahead` is zero.
    pub fn new(blob: B, size: u64, lookahead: usize) -> Self {
        assert!(lookahead > 0, "Buffer size must be greater than zero");
        Self {
            blob,
            buffer: vec![0; lookahead],
            blob_position: 0,
            blob_size: size,
            buffer_position: 0,
            buffer_valid_len: 0,
            buffer_size: lookahead,
        }
    }

    /// Returns how many valid bytes are remaining in the buffer.
    pub fn buffer_remaining(&self) -> usize {
        self.buffer_valid_len - self.buffer_position
    }

    /// Returns how many bytes remain in the blob from the current position.
    pub fn blob_remaining(&self) -> u64 {
        self.blob_size
            .saturating_sub(self.blob_position + self.buffer_position as u64)
    }

    /// Refills the buffer from the blob starting at the current blob position.
    /// Returns the number of bytes read or an error if the read failed.
    pub async fn refill(&mut self) -> Result<usize, Error> {
        // Update blob position to account for consumed bytes
        self.blob_position += self.buffer_position as u64;
        self.buffer_position = 0;
        self.buffer_valid_len = 0;

        // Calculate how many bytes remain in the blob
        let blob_remaining = self.blob_size.saturating_sub(self.blob_position);

        if blob_remaining == 0 {
            return Err(Error::BlobInsufficientLength);
        }

        // Calculate how much to read (minimum of buffer size and remaining bytes)
        let bytes_to_read = std::cmp::min(self.buffer_size, blob_remaining as usize);

        // Read the data - we only need a single read operation since we know exactly how much data is available
        if bytes_to_read < self.buffer_size {
            // Partial buffer read
            let read_buffer = &mut self.buffer[0..bytes_to_read];
            match self.blob.read_at(read_buffer, self.blob_position).await {
                Ok(()) => {
                    self.buffer_valid_len = bytes_to_read;
                    Ok(bytes_to_read)
                }
                Err(e) => Err(e),
            }
        } else {
            // Full buffer read
            match self
                .blob
                .read_at(&mut self.buffer, self.blob_position)
                .await
            {
                Ok(()) => {
                    self.buffer_valid_len = self.buffer_size;
                    Ok(self.buffer_size)
                }
                Err(e) => Err(e),
            }
        }
    }

    /// Reads exactly `size` bytes into the provided buffer.
    /// Returns an error if not enough bytes are available.
    pub async fn read_exact(&mut self, buf: &mut [u8], size: usize) -> Result<(), Error> {
        // Quick check if we have enough bytes total before attempting reads
        if (self.buffer_remaining() + self.blob_remaining() as usize) < size {
            return Err(Error::BlobInsufficientLength);
        }

        let mut bytes_read = 0;

        while bytes_read < size {
            // Check if we need to refill
            if self.buffer_position >= self.buffer_valid_len {
                self.refill().await?;
            }

            // Calculate how many bytes we can copy from the buffer
            let bytes_to_copy = std::cmp::min(
                size - bytes_read,
                self.buffer_valid_len - self.buffer_position,
            );

            // Copy bytes from buffer to output
            buf[bytes_read..(bytes_read + bytes_to_copy)].copy_from_slice(
                &self.buffer[self.buffer_position..(self.buffer_position + bytes_to_copy)],
            );

            self.buffer_position += bytes_to_copy;
            bytes_read += bytes_to_copy;
        }

        Ok(())
    }

    /// Peeks at the next `size` bytes without advancing the read position.
    /// Returns a slice to the peeked data or an error if not enough bytes are available.
    pub async fn peek(&mut self, size: usize) -> Result<&[u8], Error> {
        // Quick check if we already have enough data in the buffer
        if self.buffer_remaining() >= size {
            return Ok(&self.buffer[self.buffer_position..(self.buffer_position + size)]);
        }

        // Check if enough total bytes are available
        let total_available = self.buffer_remaining() + self.blob_remaining() as usize;
        if total_available < size {
            return Err(Error::BlobInsufficientLength);
        }

        // We need to do a more complex operation: copy remaining data to beginning,
        // then refill the rest of the buffer

        let remaining = self.buffer_remaining();
        if remaining > 0 {
            // Copy the remaining data to the beginning of the buffer
            self.buffer
                .copy_within(self.buffer_position..self.buffer_valid_len, 0);
        }

        // Update positions
        self.blob_position += self.buffer_position as u64;
        self.buffer_valid_len = remaining;
        self.buffer_position = 0;

        // Read more data into the buffer after the remaining data
        let read_pos = self.blob_position + remaining as u64;
        let bytes_blob_remaining = self.blob_size.saturating_sub(read_pos);
        let read_size = std::cmp::min(self.buffer_size - remaining, bytes_blob_remaining as usize);

        if read_size > 0 {
            match self
                .blob
                .read_at(&mut self.buffer[remaining..remaining + read_size], read_pos)
                .await
            {
                Ok(()) => {
                    self.buffer_valid_len = remaining + read_size;
                }
                Err(e) => return Err(e),
            }
        }

        if self.buffer_valid_len < size {
            return Err(Error::BlobInsufficientLength);
        }

        Ok(&self.buffer[0..size])
    }

    /// Advances the read position by `bytes` without reading data.
    pub fn advance(&mut self, bytes: usize) -> Result<(), Error> {
        if self.buffer_position + bytes > self.buffer_valid_len {
            return Err(Error::BlobInsufficientLength);
        }

        self.buffer_position += bytes;
        Ok(())
    }

    /// Returns the current absolute position in the blob.
    pub fn position(&self) -> u64 {
        self.blob_position + self.buffer_position as u64
    }
}

#[cfg(test)]
async fn task(i: usize) -> usize {
    for _ in 0..5 {
        reschedule().await;
    }
    i
}

#[cfg(test)]
pub fn run_tasks(tasks: usize, runner: crate::deterministic::Runner) -> (String, Vec<usize>) {
    runner.start(|context| async move {
        // Randomly schedule tasks
        let mut handles = FuturesUnordered::new();
        for i in 0..=tasks - 1 {
            handles.push(context.clone().spawn(move |_| task(i)));
        }

        // Collect output order
        let mut outputs = Vec::new();
        while let Some(result) = handles.next().await {
            outputs.push(result.unwrap());
        }
        assert_eq!(outputs.len(), tasks);
        (context.auditor().state(), outputs)
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{deterministic, tokio, Metrics, Storage};
    use commonware_macros::test_traced;
    use rayon::iter::{IntoParallelRefIterator, ParallelIterator};

    #[test_traced]
    fn test_create_pool() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            // Create a thread pool with 4 threads
            let pool = create_pool(context.with_label("pool"), 4).unwrap();

            // Create a vector of numbers
            let v: Vec<_> = (0..10000).collect();

            // Use the thread pool to sum the numbers
            pool.install(|| {
                assert_eq!(v.par_iter().sum::<i32>(), 10000 * 9999 / 2);
            });
        });
    }

    #[test_traced]
    fn test_rwlock() {
        let executor = deterministic::Runner::default();
        executor.start(|_| async move {
            // Create a new RwLock
            let lock = RwLock::new(100);

            // many concurrent readers
            let r1 = lock.read().await;
            let r2 = lock.read().await;
            assert_eq!(*r1 + *r2, 200);

            // exclusive writer
            drop((r1, r2)); // all readers must go away
            let mut w = lock.write().await;
            *w += 1;

            // Check the value
            assert_eq!(*w, 101);
        });
    }

    #[test_traced]
    fn test_buffer_basic() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data, 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a small buffer size
            let lookahead = 10;
            let mut reader = Buffer::new(blob, size, lookahead);

            // Read some data
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"Hello");

            // Read more data that requires a refill
            let mut buf = [0u8; 14];
            reader.read_exact(&mut buf, 14).await.unwrap();
            assert_eq!(&buf, b", world! This ");

            // Verify position
            assert_eq!(reader.position(), 19);

            // Read the rest
            let mut buf = [0u8; 10];
            reader.read_exact(&mut buf, 7).await.unwrap();
            assert_eq!(&buf[..7], b"is a te");

            // Try to read beyond the end
            let mut buf = [0u8; 5];
            let result = reader.read_exact(&mut buf, 5).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    #[should_panic(expected = "Buffer size must be greater than zero")]
    fn test_buffer_empty() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"Hello, world! This is a test.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data, 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a small buffer size
            let lookahead = 0;
            Buffer::new(blob, size, lookahead);
        });
    }

    #[test_traced]
    fn test_buffer_peek_and_advance() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"Hello, world!";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data, 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader
            let buffer_size = 20;
            let mut reader = Buffer::new(blob, size, buffer_size);

            // Peek at the first 5 bytes
            let peeked = reader.peek(5).await.unwrap();
            assert_eq!(peeked, b"Hello");

            // Position should still be 0
            assert_eq!(reader.position(), 0);

            // Advance 5 bytes
            reader.advance(5).unwrap();
            assert_eq!(reader.position(), 5);

            // Peek and read more
            let peeked = reader.peek(7).await.unwrap();
            assert_eq!(peeked, b", world");

            let mut buf = [0u8; 7];
            reader.read_exact(&mut buf, 7).await.unwrap();
            assert_eq!(&buf, b", world");

            // Position should now be 12
            assert_eq!(reader.position(), 12);

            // Read the last byte
            let mut buf = [0u8; 1];
            reader.read_exact(&mut buf, 1).await.unwrap();
            assert_eq!(&buf, b"!");

            // Should be at the end now
            assert_eq!(reader.blob_remaining(), 0);
        });
    }

    #[test_traced]
    fn test_buffer_cross_boundary() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data, 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with buffer size 10
            let buffer_size = 10;
            let mut reader = Buffer::new(blob, size, buffer_size);

            // Read data that crosses a buffer boundary
            let mut buf = [0u8; 15];
            reader.read_exact(&mut buf, 15).await.unwrap();
            assert_eq!(&buf, b"ABCDEFGHIJKLMNO");

            // Position should be 15
            assert_eq!(reader.position(), 15);

            // Peek at data that crosses another boundary
            let peeked = reader.peek(10).await.unwrap();
            assert_eq!(peeked, b"PQRSTUVWXY");

            // Read the rest
            let mut buf = [0u8; 11];
            reader.read_exact(&mut buf, 11).await.unwrap();
            assert_eq!(&buf, b"PQRSTUVWXYZ");

            // Position should be 26
            assert_eq!(reader.position(), 26);
            assert_eq!(reader.blob_remaining(), 0);
        });
    }

    #[test_traced]
    fn test_buffer_with_known_size() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"This is a test with known size limitations.";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data, 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a buffer smaller than the data
            let buffer_size = 10;
            let mut reader = Buffer::new(blob, size, buffer_size);

            // Check remaining bytes in the blob
            assert_eq!(reader.blob_remaining(), size);

            // Read half the buffer size
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"This ");

            // Check remaining after read
            assert_eq!(reader.blob_remaining(), size - 5);

            // Try to read exactly up to the size limit
            let mut buf = vec![0u8; (size - 5) as usize];
            reader
                .read_exact(&mut buf, (size - 5) as usize)
                .await
                .unwrap();
            assert_eq!(&buf, b"is a test with known size limitations.");

            // Now we should be at the end
            assert_eq!(reader.blob_remaining(), 0);

            // Trying to read more should fail
            let mut buf = [0u8; 1];
            let result = reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_buffer_large_data() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a larger blob for testing with larger data
            let data_size = 1024 * 256; // 256KB of data
            let data = vec![0x42; data_size];
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(&data, 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer with size smaller than the data
            let buffer_size = 64 * 1024; // 64KB
            let mut reader = Buffer::new(blob, size, buffer_size);

            // Read all the data in chunks
            let mut total_read = 0;
            let chunk_size = 8 * 1024; // 8KB chunks
            let mut buf = vec![0u8; chunk_size];

            while total_read < data_size {
                let to_read = std::cmp::min(chunk_size, data_size - total_read);
                reader
                    .read_exact(&mut buf[..to_read], to_read)
                    .await
                    .unwrap();

                // Verify the data is correct (all bytes should be 0x42)
                assert!(
                    buf[..to_read].iter().all(|&b| b == 0x42),
                    "Data at position {} is not correct",
                    total_read
                );

                total_read += to_read;
            }

            // Verify we read everything
            assert_eq!(total_read, data_size);

            // Trying to read more should fail
            let mut extra_buf = [0u8; 1];
            let result = reader.read_exact(&mut extra_buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_buffer_exact_size_reads() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a blob with exactly 2.5 buffer sizes of data
            let buffer_size = 1024;
            let data_size = buffer_size * 5 / 2; // 2.5 buffers
            let data = vec![0x37; data_size];

            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(&data, 0).await.unwrap();
            let size = data.len() as u64;

            let mut reader = Buffer::new(blob, size, buffer_size);

            // Read exactly one buffer size
            let mut buf1 = vec![0u8; buffer_size];
            reader.read_exact(&mut buf1, buffer_size).await.unwrap();
            assert!(buf1.iter().all(|&b| b == 0x37));

            // Read exactly one buffer size more
            let mut buf2 = vec![0u8; buffer_size];
            reader.read_exact(&mut buf2, buffer_size).await.unwrap();
            assert!(buf2.iter().all(|&b| b == 0x37));

            // Read the remaining half buffer
            let half_buffer = buffer_size / 2;
            let mut buf3 = vec![0u8; half_buffer];
            reader.read_exact(&mut buf3, half_buffer).await.unwrap();
            assert!(buf3.iter().all(|&b| b == 0x37));

            // Verify we're at the end
            assert_eq!(reader.blob_remaining(), 0);
            assert_eq!(reader.position(), size);
        });
    }
}
