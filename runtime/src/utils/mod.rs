//! Utility functions for interacting with any runtime.

#[cfg(test)]
use crate::Runner;
use crate::{Metrics, Spawner};
#[cfg(test)]
use futures::stream::{FuturesUnordered, StreamExt};
use futures::{channel::oneshot, future::Shared, FutureExt};
use rayon::{ThreadPool, ThreadPoolBuildError, ThreadPoolBuilder};
use std::{
    any::Any,
    future::Future,
    pin::Pin,
    task::{Context, Poll},
};

mod buffer;
pub use buffer::Buffer;
mod handle;
pub use handle::Handle;

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
                .spawn_blocking(move |_| thread.run());
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
    use crate::{deterministic, tokio, Blob as _, Error, Metrics, Storage};
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
            blob.write_at(data.to_vec(), 0).await.unwrap();
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
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with a small buffer size
            let lookahead = 0;
            Buffer::new(blob, size, lookahead);
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
            blob.write_at(data.to_vec(), 0).await.unwrap();
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
            blob.write_at(data.to_vec(), 0).await.unwrap();
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
            blob.write_at(data.clone(), 0).await.unwrap();
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
            blob.write_at(data.clone(), 0).await.unwrap();
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

    #[test_traced]
    fn test_buffer_seek_to() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader
            let buffer_size = 10;
            let mut reader = Buffer::new(blob, size, buffer_size);

            // Read some data to advance the position
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"ABCDE");
            assert_eq!(reader.position(), 5);

            // Seek to a specific position
            reader.seek_to(10).unwrap();
            assert_eq!(reader.position(), 10);

            // Read data from the new position
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"KLMNO");

            // Seek to beginning
            reader.seek_to(0).unwrap();
            assert_eq!(reader.position(), 0);

            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"ABCDE");

            // Seek to end
            reader.seek_to(size).unwrap();
            assert_eq!(reader.position(), size);

            // Trying to read should fail
            let mut buf = [0u8; 1];
            let result = reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));

            // Seek beyond end should fail
            let result = reader.seek_to(size + 10);
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_buffer_seek_with_refill() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with longer data
            let data = vec![0x41; 1000]; // 1000 'A' characters
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.clone(), 0).await.unwrap();
            let size = data.len() as u64;

            // Create a buffer reader with small buffer
            let buffer_size = 10;
            let mut reader = Buffer::new(blob, size, buffer_size);

            // Read some data
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();

            // Seek far ahead, past the current buffer
            reader.seek_to(500).unwrap();

            // Refill the buffer at the new position
            reader.refill().await.unwrap();

            // Read data - should get data from position 500
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(&buf, b"AAAAA"); // Should still be 'A's
            assert_eq!(reader.position(), 505);

            // Seek backwards
            reader.seek_to(100).unwrap();
            reader.refill().await.unwrap();

            // Read again - should be at position 100
            let mut buf = [0u8; 5];
            reader.read_exact(&mut buf, 5).await.unwrap();
            assert_eq!(reader.position(), 105);
        });
    }

    #[test_traced]
    fn test_buffer_truncate() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();
            let data_len = data.len() as u64;

            // Create a buffer reader
            let buffer_size = 10;
            let reader = Buffer::new(blob.clone(), data_len, buffer_size);

            // Truncate the blob to half its size
            let truncate_len = data_len / 2;
            reader.truncate(truncate_len).await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, truncate_len, "Blob should be truncated to half size");

            // Create a new buffer and read to verify truncation
            let mut new_reader = Buffer::new(blob, size, buffer_size);

            // Read the content
            let mut buf = vec![0u8; size as usize];
            new_reader
                .read_exact(&mut buf, size as usize)
                .await
                .unwrap();
            assert_eq!(&buf, b"ABCDEFGHIJKLM", "Truncated content should match");

            // Reading beyond truncated size should fail
            let mut extra_buf = [0u8; 1];
            let result = new_reader.read_exact(&mut extra_buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }

    #[test_traced]
    fn test_buffer_truncate_to_zero() {
        let executor = deterministic::Runner::default();
        executor.start(|context| async move {
            // Create a memory blob with some test data
            let data = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
            let data_len = data.len() as u64;
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0);
            blob.write_at(data.to_vec(), 0).await.unwrap();

            // Create a buffer reader
            let buffer_size = 10;
            let reader = Buffer::new(blob.clone(), data_len, buffer_size);

            // Truncate the blob to zero
            reader.truncate(0).await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open("partition", b"test").await.unwrap();
            assert_eq!(size, 0, "Blob should be truncated to zero");

            // Create a new buffer and try to read (should fail)
            let mut new_reader = Buffer::new(blob, size, buffer_size);

            // Reading from truncated blob should fail
            let mut buf = [0u8; 1];
            let result = new_reader.read_exact(&mut buf, 1).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        });
    }
}
