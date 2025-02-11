//! Execute asynchronous tasks with a configurable scheduler.
//!
//! This crate provides a collection of runtimes that can be
//! used to execute asynchronous tasks in a variety of ways. For production use,
//! the `tokio` module provides a runtime backed by [Tokio](https://tokio.rs).
//! For testing and simulation, the `deterministic` module provides a runtime
//! that allows for deterministic execution of tasks (given a fixed seed).
//!
//! # Status
//!
//! `commonware-runtime` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use std::{
    future::Future,
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use thiserror::Error;

pub mod deterministic;
pub mod mocks;
cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod tokio;
    }
}

mod utils;
pub use utils::{reschedule, Handle, Signal, Signaler};

/// Errors that can occur when interacting with the runtime.
#[derive(Error, Debug, PartialEq)]
pub enum Error {
    #[error("exited")]
    Exited,
    #[error("closed")]
    Closed,
    #[error("timeout")]
    Timeout,
    #[error("bind failed")]
    BindFailed,
    #[error("connection failed")]
    ConnectionFailed,
    #[error("write failed")]
    WriteFailed,
    #[error("read failed")]
    ReadFailed,
    #[error("send failed")]
    SendFailed,
    #[error("recv failed")]
    RecvFailed,
    #[error("partition creation failed: {0}")]
    PartitionCreationFailed(String),
    #[error("partition missing: {0}")]
    PartitionMissing(String),
    #[error("partition corrupt: {0}")]
    PartitionCorrupt(String),
    #[error("blob open failed: {0}/{1}")]
    BlobOpenFailed(String, String),
    #[error("blob missing: {0}/{1}")]
    BlobMissing(String, String),
    #[error("blob truncate failed: {0}/{1}")]
    BlobTruncateFailed(String, String),
    #[error("blob sync failed: {0}/{1}")]
    BlobSyncFailed(String, String),
    #[error("blob close failed: {0}/{1}")]
    BlobCloseFailed(String, String),
    #[error("blob insufficient length")]
    BlobInsufficientLength,
    #[error("offset overflow")]
    OffsetOverflow,
}

/// Interface that any task scheduler must implement to start
/// running tasks.
pub trait Runner {
    /// Start running a root task.
    fn start<F>(self, f: F) -> F::Output
    where
        F: Future + Send + 'static,
        F::Output: Send + 'static;
}

/// Interface that any task scheduler must implement to spawn
/// sub-tasks in a given root task.
pub trait Spawner: Clone + Send + Sync + 'static {
    /// Enqueues a task to be executed.
    ///
    /// Label can be used to track how many instances of a specific type of
    /// task have been spawned or are running concurrently (and is appended to all
    /// metrics). Label is automatically appended to the parent task labels (i.e. spawning
    /// "fun" from "have" will be labeled "have_fun").
    ///
    /// Unlike a future, a spawned task will start executing immediately (even if the caller
    /// does not await the handle).
    fn spawn<F, T>(&self, label: &str, f: F) -> Handle<T>
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;

    /// Signals the runtime to stop execution and that all outstanding tasks
    /// should perform any required cleanup and exit. This method is idempotent and
    /// can be called multiple times.
    ///
    /// This method does not actually kill any tasks but rather signals to them, using
    /// the `Signal` returned by `stopped`, that they should exit.
    fn stop(&self, value: i32);

    /// Returns an instance of a `Signal` that resolves when `stop` is called by
    /// any task.
    ///
    /// If `stop` has already been called, the returned `Signal` will resolve immediately.
    fn stopped(&self) -> Signal;
}

/// Interface that any task scheduler must implement to provide
/// time-based operations.
///
/// It is necessary to mock time to provide deterministic execution
/// of arbitrary tasks.
pub trait Clock: Clone + Send + Sync + 'static {
    /// Returns the current time.
    fn current(&self) -> SystemTime;

    /// Sleep for the given duration.
    fn sleep(&self, duration: Duration) -> impl Future<Output = ()> + Send + 'static;

    /// Sleep until the given deadline.
    fn sleep_until(&self, deadline: SystemTime) -> impl Future<Output = ()> + Send + 'static;
}

/// Interface that any runtime must implement to create
/// network connections.
pub trait Network<L, Si, St>: Clone + Send + Sync + 'static
where
    L: Listener<Si, St>,
    Si: Sink,
    St: Stream,
{
    /// Bind to the given socket address.
    fn bind(&self, socket: SocketAddr) -> impl Future<Output = Result<L, Error>> + Send;

    /// Dial the given socket address.
    fn dial(&self, socket: SocketAddr) -> impl Future<Output = Result<(Si, St), Error>> + Send;
}

/// Interface that any runtime must implement to handle
/// incoming network connections.
pub trait Listener<Si, St>: Sync + Send + 'static
where
    Si: Sink,
    St: Stream,
{
    /// Accept an incoming connection.
    fn accept(&mut self) -> impl Future<Output = Result<(SocketAddr, Si, St), Error>> + Send;
}

/// Interface that any runtime must implement to send
/// messages over a network connection.
pub trait Sink: Sync + Send + 'static {
    /// Send a message to the sink.
    fn send(&mut self, msg: &[u8]) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Interface that any runtime must implement to receive
/// messages over a network connection.
pub trait Stream: Sync + Send + 'static {
    /// Receive a message from the stream, storing it in the given buffer.
    /// Reads exactly the number of bytes that fit in the buffer.
    fn recv(&mut self, buf: &mut [u8]) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Interface to interact with storage.
///
///
/// To support storage implementations that enable concurrent reads and
/// writes, blobs are responsible for maintaining synchronization.
///
/// Storage can be backed by a local filesystem, cloud storage, etc.
pub trait Storage<B>: Clone + Send + Sync + 'static
where
    B: Blob,
{
    /// Open an existing blob in a given partition or create a new one.
    ///
    /// Multiple instances of the same blob can be opened concurrently, however,
    /// writing to the same blob concurrently may lead to undefined behavior.
    fn open(&self, partition: &str, name: &[u8]) -> impl Future<Output = Result<B, Error>> + Send;

    /// Remove a blob from a given partition.
    ///
    /// If no `name` is provided, the entire partition is removed.
    fn remove(
        &self,
        partition: &str,
        name: Option<&[u8]>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Return all blobs in a given partition.
    fn scan(&self, partition: &str) -> impl Future<Output = Result<Vec<Vec<u8>>, Error>> + Send;
}

/// Interface to read and write to a blob.
///
/// To support blob implementations that enable concurrent reads and
/// writes, blobs are responsible for maintaining synchronization.
///
/// Cloning a blob is similar to wrapping a single file descriptor in
/// a lock whereas opening a new blob (of the same name) is similar to
/// opening a new file descriptor. If multiple blobs are opened with the same
/// name, they are not expected to coordinate access to underlying storage
/// and writing to both is undefined behavior.
#[allow(clippy::len_without_is_empty)]
pub trait Blob: Clone + Send + Sync + 'static {
    /// Get the length of the blob.
    fn len(&self) -> impl Future<Output = Result<u64, Error>> + Send;

    /// Read from the blob at the given offset.
    ///
    /// `read_at` does not return the number of bytes read because it
    /// only returns once the entire buffer has been filled.
    fn read_at(
        &self,
        buf: &mut [u8],
        offset: u64,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Write to the blob at the given offset.
    fn write_at(&self, buf: &[u8], offset: u64) -> impl Future<Output = Result<(), Error>> + Send;

    /// Truncate the blob to the given length.
    fn truncate(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send;

    /// Ensure all pending data is durably persisted.
    fn sync(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// Close the blob.
    fn close(self) -> impl Future<Output = Result<(), Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use commonware_macros::select;
    use futures::{channel::mpsc, future::ready, join, SinkExt, StreamExt};
    use prometheus_client::encoding::text::encode;
    use prometheus_client::registry::Registry;
    use std::panic::{catch_unwind, AssertUnwindSafe};
    use std::sync::{Arc, Mutex};
    use utils::reschedule;

    fn test_error_future(runner: impl Runner) {
        async fn error_future() -> Result<&'static str, &'static str> {
            Err("An error occurred")
        }
        let result = runner.start(error_future());
        assert_eq!(result, Err("An error occurred"));
    }

    fn test_clock_sleep(runner: impl Runner, context: impl Spawner + Clock) {
        runner.start(async move {
            // Capture initial time
            let start = context.current();
            let sleep_duration = Duration::from_millis(10);
            context.sleep(sleep_duration).await;

            // After run, time should have advanced
            let end = context.current();
            assert!(end.duration_since(start).unwrap() >= sleep_duration);
        });
    }

    fn test_clock_sleep_until(runner: impl Runner, context: impl Spawner + Clock) {
        runner.start(async move {
            // Trigger sleep
            let now = context.current();
            context.sleep_until(now + Duration::from_millis(100)).await;

            // Ensure slept duration has elapsed
            let elapsed = now.elapsed().unwrap();
            assert!(elapsed >= Duration::from_millis(100));
        });
    }

    fn test_root_finishes(runner: impl Runner, context: impl Spawner) {
        runner.start(async move {
            context.spawn("test", async move {
                loop {
                    reschedule().await;
                }
            });
        });
    }

    fn test_spawn_abort(runner: impl Runner, context: impl Spawner) {
        runner.start(async move {
            let handle = context.spawn("test", async move {
                loop {
                    reschedule().await;
                }
            });
            handle.abort();
            assert_eq!(handle.await, Err(Error::Closed));
        });
    }

    fn test_panic_aborts_root(runner: impl Runner) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            runner.start(async move {
                panic!("blah");
            });
        }));
        result.unwrap_err();
    }

    fn test_panic_aborts_spawn(runner: impl Runner, context: impl Spawner) {
        let result = runner.start(async move {
            let result = context.spawn("test", async move {
                panic!("blah");
            });
            assert_eq!(result.await, Err(Error::Exited));
            Result::<(), Error>::Ok(())
        });

        // Ensure panic was caught
        result.unwrap();
    }

    fn test_select(runner: impl Runner) {
        runner.start(async move {
            // Test first branch
            let output = Mutex::new(0);
            select! {
                v1 = ready(1) => {
                    *output.lock().unwrap() = v1;
                },
                v2 = ready(2) => {
                    *output.lock().unwrap() = v2;
                },
            };
            assert_eq!(*output.lock().unwrap(), 1);

            // Test second branch
            select! {
                v1 = std::future::pending::<i32>() => {
                    *output.lock().unwrap() = v1;
                },
                v2 = ready(2) => {
                    *output.lock().unwrap() = v2;
                },
            };
            assert_eq!(*output.lock().unwrap(), 2);
        });
    }

    /// Ensure future fusing works as expected.
    fn test_select_loop(runner: impl Runner, context: impl Clock) {
        runner.start(async move {
            // Should hit timeout
            let (mut sender, mut receiver) = mpsc::unbounded();
            for _ in 0..2 {
                select! {
                    v = receiver.next() => {
                        panic!("unexpected value: {:?}", v);
                    },
                    _ = context.sleep(Duration::from_millis(100)) => {
                        continue;
                    },
                };
            }

            // Populate channel
            sender.send(0).await.unwrap();
            sender.send(1).await.unwrap();

            // Prefer not reading channel without losing messages
            select! {
                _ = async {} => {
                    // Skip reading from channel even though populated
                },
                v = receiver.next() => {
                    panic!("unexpected value: {:?}", v);
                },
            };

            // Process messages
            for i in 0..2 {
                select! {
                    _ = context.sleep(Duration::from_millis(100)) => {
                        panic!("timeout");
                    },
                    v = receiver.next() => {
                        assert_eq!(v.unwrap(), i);
                    },
                };
            }
        });
    }

    fn test_storage_operations<B>(runner: impl Runner, context: impl Spawner + Storage<B>)
    where
        B: Blob,
    {
        runner.start(async move {
            let partition = "test_partition";
            let name = b"test_blob";

            // Open a new blob
            let blob = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Write data to the blob
            let data = b"Hello, Storage!";
            blob.write_at(data, 0)
                .await
                .expect("Failed to write to blob");

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

            // Read data from the blob
            let mut buffer = vec![0u8; data.len()];
            blob.read_at(&mut buffer, 0)
                .await
                .expect("Failed to read from blob");
            assert_eq!(&buffer, data);

            // Get blob length
            let length = blob.len().await.expect("Failed to get blob length");
            assert_eq!(length, data.len() as u64);

            // Close the blob
            blob.close().await.expect("Failed to close blob");

            // Scan blobs in the partition
            let blobs = context
                .scan(partition)
                .await
                .expect("Failed to scan partition");
            assert!(blobs.contains(&name.to_vec()));

            // Reopen the blob
            let blob = context
                .open(partition, name)
                .await
                .expect("Failed to reopen blob");

            // Read data part of message back
            let mut buffer = vec![0u8; 7];
            blob.read_at(&mut buffer, 7)
                .await
                .expect("Failed to read data");
            assert_eq!(&buffer, b"Storage");

            // Close the blob
            blob.close().await.expect("Failed to close blob");

            // Remove the blob
            context
                .remove(partition, Some(name))
                .await
                .expect("Failed to remove blob");

            // Ensure the blob is removed
            let blobs = context
                .scan(partition)
                .await
                .expect("Failed to scan partition");
            assert!(!blobs.contains(&name.to_vec()));

            // Remove the partition
            context
                .remove(partition, None)
                .await
                .expect("Failed to remove partition");

            // Scan the partition
            let result = context.scan(partition).await;
            assert!(matches!(result, Err(Error::PartitionMissing(_))));
        });
    }

    fn test_blob_read_write<B>(runner: impl Runner, context: impl Spawner + Storage<B>)
    where
        B: Blob,
    {
        runner.start(async move {
            let partition = "test_partition";
            let name = b"test_blob_rw";

            // Open a new blob
            let blob = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Write data at different offsets
            let data1 = b"Hello";
            let data2 = b"World";
            blob.write_at(data1, 0)
                .await
                .expect("Failed to write data1");
            blob.write_at(data2, 5)
                .await
                .expect("Failed to write data2");

            // Assert that length tracks pending data
            let length = blob.len().await.expect("Failed to get blob length");
            assert_eq!(length, 10);

            // Read data back
            let mut buffer = vec![0u8; 10];
            blob.read_at(&mut buffer, 0)
                .await
                .expect("Failed to read data");
            assert_eq!(&buffer[..5], data1);
            assert_eq!(&buffer[5..], data2);

            // Rewrite data without affecting length
            let data3 = b"Store";
            blob.write_at(data3, 5)
                .await
                .expect("Failed to write data3");
            let length = blob.len().await.expect("Failed to get blob length");
            assert_eq!(length, 10);

            // Truncate the blob
            blob.truncate(5).await.expect("Failed to truncate blob");
            let length = blob.len().await.expect("Failed to get blob length");
            assert_eq!(length, 5);
            let mut buffer = vec![0u8; 5];
            blob.read_at(&mut buffer, 0)
                .await
                .expect("Failed to read data");
            assert_eq!(&buffer[..5], data1);

            // Full read after truncation
            let mut buffer = vec![0u8; 10];
            let result = blob.read_at(&mut buffer, 0).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));

            // Close the blob
            blob.close().await.expect("Failed to close blob");
        });
    }

    fn test_many_partition_read_write<B>(runner: impl Runner, context: impl Spawner + Storage<B>)
    where
        B: Blob,
    {
        runner.start(async move {
            let partitions = ["partition1", "partition2", "partition3"];
            let name = b"test_blob_rw";

            for (additional, partition) in partitions.iter().enumerate() {
                // Open a new blob
                let blob = context
                    .open(partition, name)
                    .await
                    .expect("Failed to open blob");

                // Write data at different offsets
                let data1 = b"Hello";
                let data2 = b"World";
                blob.write_at(data1, 0)
                    .await
                    .expect("Failed to write data1");
                blob.write_at(data2, 5 + additional as u64)
                    .await
                    .expect("Failed to write data2");

                // Close the blob
                blob.close().await.expect("Failed to close blob");
            }

            for (additional, partition) in partitions.iter().enumerate() {
                // Open a new blob
                let blob = context
                    .open(partition, name)
                    .await
                    .expect("Failed to open blob");

                // Read data back
                let mut buffer = vec![0u8; 10 + additional];
                blob.read_at(&mut buffer, 0)
                    .await
                    .expect("Failed to read data");
                assert_eq!(&buffer[..5], b"Hello");
                assert_eq!(&buffer[5 + additional..], b"World");

                // Close the blob
                blob.close().await.expect("Failed to close blob");
            }
        });
    }

    fn test_blob_read_past_length<B>(runner: impl Runner, context: impl Spawner + Storage<B>)
    where
        B: Blob,
    {
        runner.start(async move {
            let partition = "test_partition";
            let name = b"test_blob_rw";

            // Open a new blob
            let blob = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Read data past file length (empty file)
            let mut buffer = vec![0u8; 10];
            let result = blob.read_at(&mut buffer, 0).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));

            // Write data to the blob
            let data = b"Hello, Storage!";
            blob.write_at(data, 0)
                .await
                .expect("Failed to write to blob");

            // Read data past file length (non-empty file)
            let mut buffer = vec![0u8; 20];
            let result = blob.read_at(&mut buffer, 0).await;
            assert!(matches!(result, Err(Error::BlobInsufficientLength)));
        })
    }

    fn test_blob_clone_and_concurrent_read<B>(
        runner: impl Runner,
        context: impl Spawner + Storage<B>,
    ) where
        B: Blob,
    {
        runner.start(async move {
            let partition = "test_partition";
            let name = b"test_blob_rw";

            // Open a new blob
            let blob = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Write data to the blob
            let data = b"Hello, Storage!";
            blob.write_at(data, 0)
                .await
                .expect("Failed to write to blob");

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

            // Read data from the blob in clone
            let check1 = context.spawn("test", {
                let blob = blob.clone();
                async move {
                    let mut buffer = vec![0u8; data.len()];
                    blob.read_at(&mut buffer, 0)
                        .await
                        .expect("Failed to read from blob");
                    assert_eq!(&buffer, data);
                }
            });
            let check2 = context.spawn("test", {
                let blob = blob.clone();
                async move {
                    let mut buffer = vec![0u8; data.len()];
                    blob.read_at(&mut buffer, 0)
                        .await
                        .expect("Failed to read from blob");
                    assert_eq!(&buffer, data);
                }
            });

            // Wait for both reads to complete
            let result = join!(check1, check2);
            assert!(result.0.is_ok());
            assert!(result.1.is_ok());

            // Read data from the blob
            let mut buffer = vec![0u8; data.len()];
            blob.read_at(&mut buffer, 0)
                .await
                .expect("Failed to read from blob");
            assert_eq!(&buffer, data);

            // Get blob length
            let length = blob.len().await.expect("Failed to get blob length");
            assert_eq!(length, data.len() as u64);

            // Close the blob
            blob.close().await.expect("Failed to close blob");
        });
    }

    fn test_shutdown(runner: impl Runner, context: impl Spawner + Clock) {
        let kill = 9;
        runner.start(async move {
            // Spawn a task that waits for signal
            let before = context.spawn("before", {
                let context = context.clone();
                async move {
                    let sig = context.stopped().await;
                    assert_eq!(sig.unwrap(), kill);
                }
            });

            // Spawn a task after stop is called
            let after = context.spawn("after", {
                let context = context.clone();
                async move {
                    // Wait for stop signal
                    let mut signal = context.stopped();
                    loop {
                        select! {
                            sig = &mut signal => {
                                // Stopper resolved
                                assert_eq!(sig.unwrap(), kill);
                                break;
                            },
                            _ = context.sleep(Duration::from_millis(10)) => {
                                // Continue waiting
                            },
                        }
                    }
                }
            });

            // Sleep for a bit before stopping
            context.sleep(Duration::from_millis(50)).await;

            // Signal the task
            context.stop(kill);

            // Ensure both tasks complete
            let result = join!(before, after);
            assert!(result.0.is_ok());
            assert!(result.1.is_ok());
        });
    }

    #[test]
    fn test_deterministic_future() {
        let (runner, _, _) = deterministic::Executor::default();
        test_error_future(runner);
    }

    #[test]
    fn test_deterministic_clock_sleep() {
        let (executor, runtime, _) = deterministic::Executor::default();
        assert_eq!(runtime.current(), SystemTime::UNIX_EPOCH);
        test_clock_sleep(executor, runtime);
    }

    #[test]
    fn test_deterministic_clock_sleep_until() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_clock_sleep_until(executor, runtime);
    }

    #[test]
    fn test_deterministic_root_finishes() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_root_finishes(executor, runtime);
    }

    #[test]
    fn test_deterministic_spawn_abort() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_spawn_abort(executor, runtime);
    }

    #[test]
    fn test_deterministic_panic_aborts_root() {
        let (runner, _, _) = deterministic::Executor::default();
        test_panic_aborts_root(runner);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_deterministic_panic_aborts_spawn() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_panic_aborts_spawn(executor, runtime);
    }

    #[test]
    fn test_deterministic_select() {
        let (executor, _, _) = deterministic::Executor::default();
        test_select(executor);
    }

    #[test]
    fn test_deterministic_select_loop() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_select_loop(executor, runtime);
    }

    #[test]
    fn test_deterministic_storage_operations() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_storage_operations(executor, runtime);
    }

    #[test]
    fn test_deterministic_blob_read_write() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_blob_read_write(executor, runtime);
    }

    #[test]
    fn test_deterministic_many_partition_read_write() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_many_partition_read_write(executor, runtime);
    }

    #[test]
    fn test_deterministic_blob_read_past_length() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_blob_read_past_length(executor, runtime);
    }

    #[test]
    fn test_deterministic_blob_clone_and_concurrent_read() {
        // Run test
        let cfg = deterministic::Config {
            registry: Arc::new(Mutex::new(Registry::default())),
            ..Default::default()
        };
        let (executor, runtime, _) = deterministic::Executor::init(cfg.clone());
        test_blob_clone_and_concurrent_read(executor, runtime);

        // Ensure no blobs still open
        let mut buffer = String::new();
        encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
        assert!(buffer.contains("open_blobs 0"));
    }

    #[test]
    fn test_deterministic_shutdown() {
        let (executor, runtime, _) = deterministic::Executor::default();
        test_shutdown(executor, runtime);
    }

    #[test]
    fn test_tokio_error_future() {
        let (runner, _) = tokio::Executor::default();
        test_error_future(runner);
    }

    #[test]
    fn test_tokio_clock_sleep() {
        let (executor, runtime) = tokio::Executor::default();
        test_clock_sleep(executor, runtime);
    }

    #[test]
    fn test_tokio_clock_sleep_until() {
        let (executor, runtime) = tokio::Executor::default();
        test_clock_sleep_until(executor, runtime);
    }

    #[test]
    fn test_tokio_root_finishes() {
        let (executor, runtime) = tokio::Executor::default();
        test_root_finishes(executor, runtime);
    }

    #[test]
    fn test_tokio_spawn_abort() {
        let (executor, runtime) = tokio::Executor::default();
        test_spawn_abort(executor, runtime);
    }

    #[test]
    fn test_tokio_panic_aborts_root() {
        let (runner, _) = tokio::Executor::default();
        test_panic_aborts_root(runner);
    }

    #[test]
    fn test_tokio_panic_aborts_spawn() {
        let (executor, runtime) = tokio::Executor::default();
        test_panic_aborts_spawn(executor, runtime);
    }

    #[test]
    fn test_tokio_select() {
        let (executor, _) = tokio::Executor::default();
        test_select(executor);
    }

    #[test]
    fn test_tokio_select_loop() {
        let (executor, runtime) = tokio::Executor::default();
        test_select_loop(executor, runtime);
    }

    #[test]
    fn test_tokio_storage_operations() {
        let (executor, runtime) = tokio::Executor::default();
        test_storage_operations(executor, runtime);
    }

    #[test]
    fn test_tokio_blob_read_write() {
        let (executor, runtime) = tokio::Executor::default();
        test_blob_read_write(executor, runtime);
    }

    #[test]
    fn test_tokio_many_partition_read_write() {
        let (executor, runtime) = tokio::Executor::default();
        test_many_partition_read_write(executor, runtime);
    }

    #[test]
    fn test_tokio_blob_read_past_length() {
        let (executor, runtime) = tokio::Executor::default();
        test_blob_read_past_length(executor, runtime);
    }

    #[test]
    fn test_tokio_blob_clone_and_concurrent_read() {
        // Run test
        let cfg = tokio::Config {
            registry: Arc::new(Mutex::new(Registry::default())),
            ..Default::default()
        };
        let (executor, runtime) = tokio::Executor::init(cfg.clone());
        test_blob_clone_and_concurrent_read(executor, runtime);

        // Ensure no blobs still open
        let mut buffer = String::new();
        encode(&mut buffer, &cfg.registry.lock().unwrap()).unwrap();
        assert!(buffer.contains("open_blobs 0"));
    }

    #[test]
    fn test_tokio_shutdown() {
        let (executor, runtime) = tokio::Executor::default();
        test_shutdown(executor, runtime);
    }
}
