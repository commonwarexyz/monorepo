//! Execute asynchronous tasks with a configurable scheduler.
//!
//! This crate provides a collection of runtimes that can be
//! used to execute asynchronous tasks in a variety of ways. For production use,
//! the `tokio` module provides a runtime backed by [Tokio](https://tokio.rs).
//! For testing and simulation, the `deterministic` module provides a runtime
//! that allows for deterministic execution of tasks (given a fixed seed).
//!
//! # Terminology
//!
//! Each runtime is typically composed of an `Executor` and a `Context`. The `Executor` implements the
//! `Runner` trait and drives execution of a runtime. The `Context` implements any number of the
//! other traits to provide core functionality.
//!
//! # Status
//!
//! `commonware-runtime` is **ALPHA** software and is not yet recommended for production use. Developers should
//! expect breaking changes and occasional instability.

use commonware_utils::StableBuf;
use prometheus_client::registry::Metric;
use std::{
    future::Future,
    io::Error as IoError,
    net::SocketAddr,
    time::{Duration, SystemTime},
};
use thiserror::Error;

#[macro_use]
mod macros;

pub mod deterministic;
pub mod mocks;
cfg_if::cfg_if! {
    if #[cfg(not(target_arch = "wasm32"))] {
        pub mod tokio;
        pub mod benchmarks;
    }
}
mod network;
mod storage;
pub mod telemetry;
mod utils;
pub use utils::*;
#[cfg(any(feature = "iouring-storage", feature = "iouring-network"))]
mod iouring;

/// Prefix for runtime metrics.
const METRICS_PREFIX: &str = "runtime";

/// Errors that can occur when interacting with the runtime.
#[derive(Error, Debug)]
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
    #[error("blob open failed: {0}/{1} error: {2}")]
    BlobOpenFailed(String, String, IoError),
    #[error("blob missing: {0}/{1}")]
    BlobMissing(String, String),
    #[error("blob resize failed: {0}/{1} error: {2}")]
    BlobResizeFailed(String, String, IoError),
    #[error("blob sync failed: {0}/{1} error: {2}")]
    BlobSyncFailed(String, String, IoError),
    #[error("blob close failed: {0}/{1} error: {2}")]
    BlobCloseFailed(String, String, IoError),
    #[error("blob insufficient length")]
    BlobInsufficientLength,
    #[error("offset overflow")]
    OffsetOverflow,
    #[error("io error: {0}")]
    Io(#[from] IoError),
}

/// Interface that any task scheduler must implement to start
/// running tasks.
pub trait Runner {
    /// Context defines the environment available to tasks.
    /// Example of possible services provided by the context include:
    /// - [Clock] for time-based operations
    /// - [Network] for network operations
    /// - [Storage] for storage operations
    type Context;

    /// Start running a root task.
    fn start<F, Fut>(self, f: F) -> Fut::Output
    where
        F: FnOnce(Self::Context) -> Fut,
        Fut: Future;
}

/// Interface that any task scheduler must implement to spawn tasks.
pub trait Spawner: Clone + Send + Sync + 'static {
    /// Enqueue a task to be executed.
    ///
    /// Unlike a future, a spawned task will start executing immediately (even if the caller
    /// does not await the handle).
    ///
    /// Spawned tasks consume the context used to create them. This ensures that context cannot
    /// be shared between tasks and that a task's context always comes from somewhere.
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static;

    /// Enqueue a task to be executed (without consuming the context).
    ///
    /// The semantics are the same as [Spawner::spawn].
    ///
    /// # Warning
    ///
    /// If this function is used to spawn multiple tasks from the same context, the runtime will panic
    /// to prevent accidental misuse.
    fn spawn_ref<F, T>(&mut self) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;

    /// Enqueue a blocking task to be executed.
    ///
    /// This method is designed for synchronous, potentially long-running operations. Tasks can either
    /// be executed in a shared thread (tasks that are expected to finish on their own) or a dedicated
    /// thread (tasks that are expected to run indefinitely).
    ///
    /// The task starts executing immediately, and the returned handle can be awaited to retrieve the
    /// result.
    ///
    /// # Motivation
    ///
    /// Most runtimes allocate a limited number of threads for executing async tasks, running whatever
    /// isn't waiting. If blocking tasks are spawned this way, they can dramatically reduce the efficiency
    /// of said runtimes.
    ///
    /// # Warning
    ///
    /// Blocking tasks cannot be aborted.
    fn spawn_blocking<F, T>(self, dedicated: bool, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> T + Send + 'static,
        T: Send + 'static;

    /// Enqueue a blocking task to be executed (without consuming the context).
    ///
    /// The semantics are the same as [Spawner::spawn_blocking].
    ///
    /// # Warning
    ///
    /// If this function is used to spawn multiple tasks from the same context,
    /// the runtime will panic to prevent accidental misuse.
    fn spawn_blocking_ref<F, T>(
        &mut self,
        dedicated: bool,
    ) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: FnOnce() -> T + Send + 'static,
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

/// Interface to register and encode metrics.
pub trait Metrics: Clone + Send + Sync + 'static {
    /// Get the current label of the context.
    fn label(&self) -> String;

    /// Create a new instance of `Metrics` with the given label appended to the end
    /// of the current `Metrics` label.
    ///
    /// This is commonly used to create a nested context for `register`.
    ///
    /// It is not permitted for any implementation to use `METRICS_PREFIX` as the start of a
    /// label (reserved for metrics for the runtime).
    fn with_label(&self, label: &str) -> Self;

    /// Prefix the given label with the current context's label.
    ///
    /// Unlike `with_label`, this method does not create a new context.
    fn scoped_label(&self, label: &str) -> String {
        let label = if self.label().is_empty() {
            label.to_string()
        } else {
            format!("{}_{}", self.label(), label)
        };
        assert!(
            !label.starts_with(METRICS_PREFIX),
            "using runtime label is not allowed"
        );
        label
    }

    /// Register a metric with the runtime.
    ///
    /// Any registered metric will include (as a prefix) the label of the current context.
    fn register<N: Into<String>, H: Into<String>>(&self, name: N, help: H, metric: impl Metric);

    /// Encode all metrics into a buffer.
    fn encode(&self) -> String;
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

/// Syntactic sugar for the type of [Sink] used by a given [Network] N.
pub type SinkOf<N> = <<N as Network>::Listener as Listener>::Sink;

/// Syntactic sugar for the type of [Stream] used by a given [Network] N.
pub type StreamOf<N> = <<N as Network>::Listener as Listener>::Stream;

/// Syntactic sugar for the type of [Listener] used by a given [Network] N.
pub type ListenerOf<N> = <N as crate::Network>::Listener;

/// Interface that any runtime must implement to create
/// network connections.
pub trait Network: Clone + Send + Sync + 'static {
    /// The type of [Listener] that's returned when binding to a socket.
    /// Accepting a connection returns a [Sink] and [Stream] which are defined
    /// by the [Listener] and used to send and receive data over the connection.
    type Listener: Listener;

    /// Bind to the given socket address.
    fn bind(
        &self,
        socket: SocketAddr,
    ) -> impl Future<Output = Result<Self::Listener, Error>> + Send;

    /// Dial the given socket address.
    fn dial(
        &self,
        socket: SocketAddr,
    ) -> impl Future<Output = Result<(SinkOf<Self>, StreamOf<Self>), Error>> + Send;
}

/// Interface that any runtime must implement to handle
/// incoming network connections.
pub trait Listener: Sync + Send + 'static {
    /// The type of [Sink] that's returned when accepting a connection.
    /// This is used to send data to the remote connection.
    type Sink: Sink;
    /// The type of [Stream] that's returned when accepting a connection.
    /// This is used to receive data from the remote connection.
    type Stream: Stream;

    /// Accept an incoming connection.
    fn accept(
        &mut self,
    ) -> impl Future<Output = Result<(SocketAddr, Self::Sink, Self::Stream), Error>> + Send;

    /// Returns the local address of the listener.
    fn local_addr(&self) -> Result<SocketAddr, std::io::Error>;
}

/// Interface that any runtime must implement to send
/// messages over a network connection.
pub trait Sink: Sync + Send + 'static {
    /// Send a message to the sink.
    fn send(
        &mut self,
        msg: impl Into<StableBuf> + Send,
    ) -> impl Future<Output = Result<(), Error>> + Send;
}

/// Interface that any runtime must implement to receive
/// messages over a network connection.
pub trait Stream: Sync + Send + 'static {
    /// Receive a message from the stream, storing it in the given buffer.
    /// Reads exactly the number of bytes that fit in the buffer.
    fn recv(
        &mut self,
        buf: impl Into<StableBuf> + Send,
    ) -> impl Future<Output = Result<StableBuf, Error>> + Send;
}

/// Interface to interact with storage.
///
///
/// To support storage implementations that enable concurrent reads and
/// writes, blobs are responsible for maintaining synchronization.
///
/// Storage can be backed by a local filesystem, cloud storage, etc.
pub trait Storage: Clone + Send + Sync + 'static {
    /// The readable/writeable storage buffer that can be opened by this Storage.
    type Blob: Blob;

    /// Open an existing blob in a given partition or create a new one, returning
    /// the blob and its length.
    ///
    /// Multiple instances of the same blob can be opened concurrently, however,
    /// writing to the same blob concurrently may lead to undefined behavior.
    fn open(
        &self,
        partition: &str,
        name: &[u8],
    ) -> impl Future<Output = Result<(Self::Blob, u64), Error>> + Send;

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
    /// Read from the blob at the given offset.
    ///
    /// `read_at` does not return the number of bytes read because it
    /// only returns once the entire buffer has been filled.
    fn read_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> impl Future<Output = Result<StableBuf, Error>> + Send;

    /// Write `buf` to the blob at the given offset.
    fn write_at(
        &self,
        buf: impl Into<StableBuf> + Send,
        offset: u64,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Resize the blob to the given length.
    ///
    /// If the length is greater than the current length, the blob is extended with zeros.
    /// If the length is less than the current length, the blob is resized.
    fn resize(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send;

    /// Ensure all pending data is durably persisted.
    fn sync(&self) -> impl Future<Output = Result<(), Error>> + Send;

    /// Close the blob.
    fn close(self) -> impl Future<Output = Result<(), Error>> + Send;
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_macros::select;
    use futures::{
        channel::{mpsc, oneshot},
        future::ready,
        join, SinkExt, StreamExt,
    };
    use prometheus_client::metrics::counter::Counter;
    use std::{
        collections::HashMap,
        panic::{catch_unwind, AssertUnwindSafe},
        str::FromStr,
        sync::Mutex,
    };
    use tracing::{error, Level};
    use utils::reschedule;

    fn test_error_future<R: Runner>(runner: R) {
        async fn error_future() -> Result<&'static str, &'static str> {
            Err("An error occurred")
        }
        let result = runner.start(|_| error_future());
        assert_eq!(result, Err("An error occurred"));
    }

    fn test_clock_sleep<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            // Capture initial time
            let start = context.current();
            let sleep_duration = Duration::from_millis(10);
            context.sleep(sleep_duration).await;

            // After run, time should have advanced
            let end = context.current();
            assert!(end.duration_since(start).unwrap() >= sleep_duration);
        });
    }

    fn test_clock_sleep_until<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            // Trigger sleep
            let now = context.current();
            context.sleep_until(now + Duration::from_millis(100)).await;

            // Ensure slept duration has elapsed
            let elapsed = now.elapsed().unwrap();
            assert!(elapsed >= Duration::from_millis(100));
        });
    }

    fn test_root_finishes<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            context.spawn(|_| async move {
                loop {
                    reschedule().await;
                }
            });
        });
    }

    fn test_spawn_abort<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let handle = context.spawn(|_| async move {
                loop {
                    reschedule().await;
                }
            });
            handle.abort();
            assert!(matches!(handle.await, Err(Error::Closed)));
        });
    }

    fn test_panic_aborts_root<R: Runner>(runner: R) {
        let result = catch_unwind(AssertUnwindSafe(|| {
            runner.start(|_| async move {
                panic!("blah");
            });
        }));
        result.unwrap_err();
    }

    fn test_panic_aborts_spawn<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        let result = runner.start(|context| async move {
            let result = context.spawn(|_| async move {
                panic!("blah");
            });
            assert!(matches!(result.await, Err(Error::Exited)));
            Result::<(), Error>::Ok(())
        });

        // Ensure panic was caught
        result.unwrap();
    }

    fn test_select<R: Runner>(runner: R) {
        runner.start(|_| async move {
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
    fn test_select_loop<R: Runner>(runner: R)
    where
        R::Context: Clock,
    {
        runner.start(|context| async move {
            // Should hit timeout
            let (mut sender, mut receiver) = mpsc::unbounded();
            for _ in 0..2 {
                select! {
                    v = receiver.next() => {
                        panic!("unexpected value: {v:?}");
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
                    panic!("unexpected value: {v:?}");
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

    fn test_storage_operations<R: Runner>(runner: R)
    where
        R::Context: Storage,
    {
        runner.start(|context| async move {
            let partition = "test_partition";
            let name = b"test_blob";

            // Open a new blob
            let (blob, _) = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Write data to the blob
            let data = b"Hello, Storage!";
            blob.write_at(Vec::from(data), 0)
                .await
                .expect("Failed to write to blob");

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

            // Read data from the blob
            let read = blob
                .read_at(vec![0; data.len()], 0)
                .await
                .expect("Failed to read from blob");
            assert_eq!(read.as_ref(), data);

            // Close the blob
            blob.close().await.expect("Failed to close blob");

            // Scan blobs in the partition
            let blobs = context
                .scan(partition)
                .await
                .expect("Failed to scan partition");
            assert!(blobs.contains(&name.to_vec()));

            // Reopen the blob
            let (blob, len) = context
                .open(partition, name)
                .await
                .expect("Failed to reopen blob");
            assert_eq!(len, data.len() as u64);

            // Read data part of message back
            let read = blob
                .read_at(vec![0u8; 7], 7)
                .await
                .expect("Failed to read data");
            assert_eq!(read.as_ref(), b"Storage");

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

    fn test_blob_read_write<R: Runner>(runner: R)
    where
        R::Context: Storage,
    {
        runner.start(|context| async move {
            let partition = "test_partition";
            let name = b"test_blob_rw";

            // Open a new blob
            let (blob, _) = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Write data at different offsets
            let data1 = b"Hello";
            let data2 = b"World";
            blob.write_at(Vec::from(data1), 0)
                .await
                .expect("Failed to write data1");
            blob.write_at(Vec::from(data2), 5)
                .await
                .expect("Failed to write data2");

            // Read data back
            let read = blob
                .read_at(vec![0u8; 10], 0)
                .await
                .expect("Failed to read data");
            assert_eq!(&read.as_ref()[..5], data1);
            assert_eq!(&read.as_ref()[5..], data2);

            // Read past end of blob
            let result = blob.read_at(vec![0u8; 10], 10).await;
            assert!(result.is_err());

            // Rewrite data without affecting length
            let data3 = b"Store";
            blob.write_at(Vec::from(data3), 5)
                .await
                .expect("Failed to write data3");

            // Read data back
            let read = blob
                .read_at(vec![0u8; 10], 0)
                .await
                .expect("Failed to read data");
            assert_eq!(&read.as_ref()[..5], data1);
            assert_eq!(&read.as_ref()[5..], data3);

            // Read past end of blob
            let result = blob.read_at(vec![0u8; 10], 10).await;
            assert!(result.is_err());
        });
    }

    fn test_blob_resize<R: Runner>(runner: R)
    where
        R::Context: Storage,
    {
        runner.start(|context| async move {
            let partition = "test_partition_resize";
            let name = b"test_blob_resize";

            // Open and write to a new blob
            let (blob, _) = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            let data = b"some data";
            blob.write_at(data.to_vec(), 0)
                .await
                .expect("Failed to write");
            blob.sync().await.expect("Failed to sync after write");
            blob.close()
                .await
                .expect("Failed to close blob after writing");

            // Re-open and check length
            let (blob, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, data.len() as u64);

            // Resize to extend the file
            let new_len = (data.len() as u64) * 2;
            blob.resize(new_len)
                .await
                .expect("Failed to resize to extend");
            blob.sync().await.expect("Failed to sync after resize");
            blob.close()
                .await
                .expect("Failed to close blob after resizing");

            // Re-open and check length again
            let (blob, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, new_len);

            // Read original data
            let read_buf = blob.read_at(vec![0; data.len()], 0).await.unwrap();
            assert_eq!(read_buf.as_ref(), data);

            // Read extended part (should be zeros)
            let extended_part = blob
                .read_at(vec![0; data.len()], data.len() as u64)
                .await
                .unwrap();
            assert_eq!(extended_part.as_ref(), vec![0; data.len()].as_slice());

            // Truncate the blob
            blob.resize(data.len() as u64).await.unwrap();
            blob.sync().await.unwrap();
            blob.close().await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open(partition, name).await.unwrap();
            assert_eq!(size, data.len() as u64);

            // Read truncated data
            let read_buf = blob.read_at(vec![0; data.len()], 0).await.unwrap();
            assert_eq!(read_buf.as_ref(), data);
            blob.close().await.unwrap();
        });
    }

    fn test_many_partition_read_write<R: Runner>(runner: R)
    where
        R::Context: Storage,
    {
        runner.start(|context| async move {
            let partitions = ["partition1", "partition2", "partition3"];
            let name = b"test_blob_rw";
            let data1 = b"Hello";
            let data2 = b"World";

            for (additional, partition) in partitions.iter().enumerate() {
                // Open a new blob
                let (blob, _) = context
                    .open(partition, name)
                    .await
                    .expect("Failed to open blob");

                // Write data at different offsets
                blob.write_at(Vec::from(data1), 0)
                    .await
                    .expect("Failed to write data1");
                blob.write_at(Vec::from(data2), 5 + additional as u64)
                    .await
                    .expect("Failed to write data2");

                // Close the blob
                blob.close().await.expect("Failed to close blob");
            }

            for (additional, partition) in partitions.iter().enumerate() {
                // Open a new blob
                let (blob, len) = context
                    .open(partition, name)
                    .await
                    .expect("Failed to open blob");
                assert_eq!(len, (data1.len() + data2.len() + additional) as u64);

                // Read data back
                let read = blob
                    .read_at(vec![0u8; 10 + additional], 0)
                    .await
                    .expect("Failed to read data");
                assert_eq!(&read.as_ref()[..5], b"Hello");
                assert_eq!(&read.as_ref()[5 + additional..], b"World");

                // Close the blob
                blob.close().await.expect("Failed to close blob");
            }
        });
    }

    fn test_blob_read_past_length<R: Runner>(runner: R)
    where
        R::Context: Storage,
    {
        runner.start(|context| async move {
            let partition = "test_partition";
            let name = b"test_blob_rw";

            // Open a new blob
            let (blob, _) = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Read data past file length (empty file)
            let result = blob.read_at(vec![0u8; 10], 0).await;
            assert!(result.is_err());

            // Write data to the blob
            let data = b"Hello, Storage!".to_vec();
            blob.write_at(data, 0)
                .await
                .expect("Failed to write to blob");

            // Read data past file length (non-empty file)
            let result = blob.read_at(vec![0u8; 20], 0).await;
            assert!(result.is_err());
        })
    }

    fn test_blob_clone_and_concurrent_read<R: Runner>(runner: R)
    where
        R::Context: Spawner + Storage + Metrics,
    {
        runner.start(|context| async move {
            let partition = "test_partition";
            let name = b"test_blob_rw";

            // Open a new blob
            let (blob, _) = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");

            // Write data to the blob
            let data = b"Hello, Storage!";
            blob.write_at(Vec::from(data), 0)
                .await
                .expect("Failed to write to blob");

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

            // Read data from the blob in clone
            let check1 = context.with_label("check1").spawn({
                let blob = blob.clone();
                move |_| async move {
                    let read = blob
                        .read_at(vec![0u8; data.len()], 0)
                        .await
                        .expect("Failed to read from blob");
                    assert_eq!(read.as_ref(), data);
                }
            });
            let check2 = context.with_label("check2").spawn({
                let blob = blob.clone();
                move |_| async move {
                    let read = blob
                        .read_at(vec![0; data.len()], 0)
                        .await
                        .expect("Failed to read from blob");
                    assert_eq!(read.as_ref(), data);
                }
            });

            // Wait for both reads to complete
            let result = join!(check1, check2);
            assert!(result.0.is_ok());
            assert!(result.1.is_ok());

            // Read data from the blob
            let read = blob
                .read_at(vec![0; data.len()], 0)
                .await
                .expect("Failed to read from blob");
            assert_eq!(read.as_ref(), data);

            // Close the blob
            blob.close().await.expect("Failed to close blob");

            // Ensure no blobs still open
            let buffer = context.encode();
            assert!(buffer.contains("open_blobs 0"));
        });
    }

    fn test_shutdown<R: Runner>(runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill = 9;
        runner.start(|context| async move {
            // Spawn a task that waits for signal
            let before = context
                .with_label("before")
                .spawn(move |context| async move {
                    let sig = context.stopped().await;
                    assert_eq!(sig.unwrap(), kill);
                });

            // Spawn a task after stop is called
            let after = context
                .with_label("after")
                .spawn(move |context| async move {
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

    fn test_spawn_ref<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|mut context| async move {
            let handle = context.spawn_ref();
            let result = handle(async move { 42 }).await;
            assert!(matches!(result, Ok(42)));
        });
    }

    fn test_spawn_ref_duplicate<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|mut context| async move {
            let handle = context.spawn_ref();
            let result = handle(async move { 42 }).await;
            assert!(matches!(result, Ok(42)));

            // Ensure context is consumed
            let handle = context.spawn_ref();
            let result = handle(async move { 42 }).await;
            assert!(matches!(result, Ok(42)));
        });
    }

    fn test_spawn_duplicate<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|mut context| async move {
            let handle = context.spawn_ref();
            let result = handle(async move { 42 }).await;
            assert!(matches!(result, Ok(42)));

            // Ensure context is consumed
            context.spawn(|_| async move { 42 });
        });
    }

    fn test_spawn_blocking<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let handle = context.spawn_blocking(dedicated, |_| 42);
            let result = handle.await;
            assert!(matches!(result, Ok(42)));
        });
    }

    fn test_spawn_blocking_ref<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|mut context| async move {
            let spawn = context.spawn_blocking_ref(dedicated);
            let handle = spawn(|| 42);
            let result = handle.await;
            assert!(matches!(result, Ok(42)));
        });
    }

    fn test_spawn_blocking_ref_duplicate<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|mut context| async move {
            let spawn = context.spawn_blocking_ref(dedicated);
            let result = spawn(|| 42).await;
            assert!(matches!(result, Ok(42)));

            // Ensure context is consumed
            context.spawn_blocking(dedicated, |_| 42);
        });
    }

    fn test_spawn_blocking_abort<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            // Create task
            let (sender, mut receiver) = oneshot::channel();
            let handle = context.spawn_blocking(dedicated, move |_| {
                // Wait for abort to be called
                loop {
                    if receiver.try_recv().is_ok() {
                        break;
                    }
                }

                // Perform a long-running operation
                let mut count = 0;
                loop {
                    count += 1;
                    if count >= 100_000_000 {
                        break;
                    }
                }
                count
            });

            // Abort the task
            //
            // If there was an `.await` prior to sending a message over the oneshot, this test
            // could deadlock (depending on the runtime implementation) because the blocking task
            // would never yield (preventing send from being called).
            handle.abort();
            sender.send(()).unwrap();

            // Wait for the task to complete
            assert!(matches!(handle.await, Ok(100_000_000)));
        });
    }

    fn test_metrics<R: Runner>(runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Assert label
            assert_eq!(context.label(), "");

            // Register a metric
            let counter = Counter::<u64>::default();
            context.register("test", "test", counter.clone());

            // Increment the counter
            counter.inc();

            // Encode metrics
            let buffer = context.encode();
            assert!(buffer.contains("test_total 1"));

            // Nested context
            let context = context.with_label("nested");
            let nested_counter = Counter::<u64>::default();
            context.register("test", "test", nested_counter.clone());

            // Increment the counter
            nested_counter.inc();

            // Encode metrics
            let buffer = context.encode();
            assert!(buffer.contains("nested_test_total 1"));
            assert!(buffer.contains("test_total 1"));
        });
    }

    fn test_metrics_label<R: Runner>(runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            context.with_label(METRICS_PREFIX);
        })
    }

    #[test]
    fn test_deterministic_future() {
        let runner = deterministic::Runner::default();
        test_error_future(runner);
    }

    #[test]
    fn test_deterministic_clock_sleep() {
        let executor = deterministic::Runner::default();
        test_clock_sleep(executor);
    }

    #[test]
    fn test_deterministic_clock_sleep_until() {
        let executor = deterministic::Runner::default();
        test_clock_sleep_until(executor);
    }

    #[test]
    fn test_deterministic_root_finishes() {
        let executor = deterministic::Runner::default();
        test_root_finishes(executor);
    }

    #[test]
    fn test_deterministic_spawn_abort() {
        let executor = deterministic::Runner::default();
        test_spawn_abort(executor);
    }

    #[test]
    fn test_deterministic_panic_aborts_root() {
        let runner = deterministic::Runner::default();
        test_panic_aborts_root(runner);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_deterministic_panic_aborts_spawn() {
        let executor = deterministic::Runner::default();
        test_panic_aborts_spawn(executor);
    }

    #[test]
    fn test_deterministic_select() {
        let executor = deterministic::Runner::default();
        test_select(executor);
    }

    #[test]
    fn test_deterministic_select_loop() {
        let executor = deterministic::Runner::default();
        test_select_loop(executor);
    }

    #[test]
    fn test_deterministic_storage_operations() {
        let executor = deterministic::Runner::default();
        test_storage_operations(executor);
    }

    #[test]
    fn test_deterministic_blob_read_write() {
        let executor = deterministic::Runner::default();
        test_blob_read_write(executor);
    }

    #[test]
    fn test_deterministic_blob_resize() {
        let executor = deterministic::Runner::default();
        test_blob_resize(executor);
    }

    #[test]
    fn test_deterministic_many_partition_read_write() {
        let executor = deterministic::Runner::default();
        test_many_partition_read_write(executor);
    }

    #[test]
    fn test_deterministic_blob_read_past_length() {
        let executor = deterministic::Runner::default();
        test_blob_read_past_length(executor);
    }

    #[test]
    fn test_deterministic_blob_clone_and_concurrent_read() {
        // Run test
        let executor = deterministic::Runner::default();
        test_blob_clone_and_concurrent_read(executor);
    }

    #[test]
    fn test_deterministic_shutdown() {
        let executor = deterministic::Runner::default();
        test_shutdown(executor);
    }

    #[test]
    fn test_deterministic_spawn_ref() {
        let executor = deterministic::Runner::default();
        test_spawn_ref(executor);
    }

    #[test]
    #[should_panic]
    fn test_deterministic_spawn_ref_duplicate() {
        let executor = deterministic::Runner::default();
        test_spawn_ref_duplicate(executor);
    }

    #[test]
    #[should_panic]
    fn test_deterministic_spawn_duplicate() {
        let executor = deterministic::Runner::default();
        test_spawn_duplicate(executor);
    }

    #[test]
    fn test_deterministic_spawn_blocking() {
        for dedicated in [false, true] {
            let executor = deterministic::Runner::default();
            test_spawn_blocking(executor, dedicated);
        }
    }

    #[test]
    #[should_panic(expected = "blocking task panicked")]
    fn test_deterministic_spawn_blocking_panic() {
        for dedicated in [false, true] {
            let executor = deterministic::Runner::default();
            executor.start(|context| async move {
                let handle = context.spawn_blocking(dedicated, |_| {
                    panic!("blocking task panicked");
                });
                handle.await.unwrap();
            });
        }
    }

    #[test]
    fn test_deterministic_spawn_blocking_abort() {
        for dedicated in [false, true] {
            let executor = deterministic::Runner::default();
            test_spawn_blocking_abort(executor, dedicated);
        }
    }

    #[test]
    fn test_deterministic_spawn_blocking_ref() {
        for dedicated in [false, true] {
            let executor = deterministic::Runner::default();
            test_spawn_blocking_ref(executor, dedicated);
        }
    }

    #[test]
    #[should_panic]
    fn test_deterministic_spawn_blocking_ref_duplicate() {
        for dedicated in [false, true] {
            let executor = deterministic::Runner::default();
            test_spawn_blocking_ref_duplicate(executor, dedicated);
        }
    }

    #[test]
    fn test_deterministic_metrics() {
        let executor = deterministic::Runner::default();
        test_metrics(executor);
    }

    #[test]
    #[should_panic]
    fn test_deterministic_metrics_label() {
        let executor = deterministic::Runner::default();
        test_metrics_label(executor);
    }

    #[test]
    fn test_tokio_error_future() {
        let runner = tokio::Runner::default();
        test_error_future(runner);
    }

    #[test]
    fn test_tokio_clock_sleep() {
        let executor = tokio::Runner::default();
        test_clock_sleep(executor);
    }

    #[test]
    fn test_tokio_clock_sleep_until() {
        let executor = tokio::Runner::default();
        test_clock_sleep_until(executor);
    }

    #[test]
    fn test_tokio_root_finishes() {
        let executor = tokio::Runner::default();
        test_root_finishes(executor);
    }

    #[test]
    fn test_tokio_spawn_abort() {
        let executor = tokio::Runner::default();
        test_spawn_abort(executor);
    }

    #[test]
    fn test_tokio_panic_aborts_root() {
        let executor = tokio::Runner::default();
        test_panic_aborts_root(executor);
    }

    #[test]
    fn test_tokio_panic_aborts_spawn() {
        let executor = tokio::Runner::default();
        test_panic_aborts_spawn(executor);
    }

    #[test]
    fn test_tokio_select() {
        let executor = tokio::Runner::default();
        test_select(executor);
    }

    #[test]
    fn test_tokio_select_loop() {
        let executor = tokio::Runner::default();
        test_select_loop(executor);
    }

    #[test]
    fn test_tokio_storage_operations() {
        let executor = tokio::Runner::default();
        test_storage_operations(executor);
    }

    #[test]
    fn test_tokio_blob_read_write() {
        let executor = tokio::Runner::default();
        test_blob_read_write(executor);
    }

    #[test]
    fn test_tokio_blob_resize() {
        let executor = tokio::Runner::default();
        test_blob_resize(executor);
    }

    #[test]
    fn test_tokio_many_partition_read_write() {
        let executor = tokio::Runner::default();
        test_many_partition_read_write(executor);
    }

    #[test]
    fn test_tokio_blob_read_past_length() {
        let executor = tokio::Runner::default();
        test_blob_read_past_length(executor);
    }

    #[test]
    fn test_tokio_blob_clone_and_concurrent_read() {
        // Run test
        let executor = tokio::Runner::default();
        test_blob_clone_and_concurrent_read(executor);
    }

    #[test]
    fn test_tokio_shutdown() {
        let executor = tokio::Runner::default();
        test_shutdown(executor);
    }

    #[test]
    fn test_tokio_spawn_ref() {
        let executor = tokio::Runner::default();
        test_spawn_ref(executor);
    }

    #[test]
    #[should_panic]
    fn test_tokio_spawn_ref_duplicate() {
        let executor = tokio::Runner::default();
        test_spawn_ref_duplicate(executor);
    }

    #[test]
    #[should_panic]
    fn test_tokio_spawn_duplicate() {
        let executor = tokio::Runner::default();
        test_spawn_duplicate(executor);
    }

    #[test]
    fn test_tokio_spawn_blocking() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            test_spawn_blocking(executor, dedicated);
        }
    }

    #[test]
    fn test_tokio_spawn_blocking_panic() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            executor.start(|context| async move {
                let handle = context.spawn_blocking(dedicated, |_| {
                    panic!("blocking task panicked");
                });
                let result = handle.await;
                assert!(matches!(result, Err(Error::Exited)));
            });
        }
    }

    #[test]
    fn test_tokio_spawn_blocking_abort() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            test_spawn_blocking_abort(executor, dedicated);
        }
    }

    #[test]
    fn test_tokio_spawn_blocking_ref() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            test_spawn_blocking_ref(executor, dedicated);
        }
    }

    #[test]
    #[should_panic]
    fn test_tokio_spawn_blocking_ref_duplicate() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            test_spawn_blocking_ref_duplicate(executor, dedicated);
        }
    }

    #[test]
    fn test_tokio_metrics() {
        let executor = tokio::Runner::default();
        test_metrics(executor);
    }

    #[test]
    #[should_panic]
    fn test_tokio_metrics_label() {
        let executor = tokio::Runner::default();
        test_metrics_label(executor);
    }

    #[test]
    fn test_tokio_telemetry() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            // Define the server address
            let address = SocketAddr::from_str("127.0.0.1:8000").unwrap();

            // Configure telemetry
            tokio::telemetry::init(
                context.with_label("metrics"),
                tokio::telemetry::Logging {
                    level: Level::INFO,
                    json: false,
                },
                Some(address),
                None,
            );

            // Register a test metric
            let counter: Counter<u64> = Counter::default();
            context.register("test_counter", "Test counter", counter.clone());
            counter.inc();

            // Helper functions to parse HTTP response
            async fn read_line<St: Stream>(stream: &mut St) -> Result<String, Error> {
                let mut line = Vec::new();
                loop {
                    let byte = stream.recv(vec![0; 1]).await?;
                    if byte[0] == b'\n' {
                        if line.last() == Some(&b'\r') {
                            line.pop(); // Remove trailing \r
                        }
                        break;
                    }
                    line.push(byte[0]);
                }
                String::from_utf8(line).map_err(|_| Error::ReadFailed)
            }

            async fn read_headers<St: Stream>(
                stream: &mut St,
            ) -> Result<HashMap<String, String>, Error> {
                let mut headers = HashMap::new();
                loop {
                    let line = read_line(stream).await?;
                    if line.is_empty() {
                        break;
                    }
                    let parts: Vec<&str> = line.splitn(2, ": ").collect();
                    if parts.len() == 2 {
                        headers.insert(parts[0].to_string(), parts[1].to_string());
                    }
                }
                Ok(headers)
            }

            async fn read_body<St: Stream>(
                stream: &mut St,
                content_length: usize,
            ) -> Result<String, Error> {
                let read = stream.recv(vec![0; content_length]).await?;
                String::from_utf8(read.into()).map_err(|_| Error::ReadFailed)
            }

            // Simulate a client connecting to the server
            let client_handle = context
                .with_label("client")
                .spawn(move |context| async move {
                    let (mut sink, mut stream) = loop {
                        match context.dial(address).await {
                            Ok((sink, stream)) => break (sink, stream),
                            Err(e) => {
                                // The client may be polled before the server is ready, that's alright!
                                error!(err =?e, "failed to connect");
                                context.sleep(Duration::from_millis(10)).await;
                            }
                        }
                    };

                    // Send a GET request to the server
                    let request = format!(
                        "GET /metrics HTTP/1.1\r\nHost: {address}\r\nConnection: close\r\n\r\n"
                    );
                    sink.send(Bytes::from(request).to_vec()).await.unwrap();

                    // Read and verify the HTTP status line
                    let status_line = read_line(&mut stream).await.unwrap();
                    assert_eq!(status_line, "HTTP/1.1 200 OK");

                    // Read and parse headers
                    let headers = read_headers(&mut stream).await.unwrap();
                    println!("Headers: {headers:?}");
                    let content_length = headers
                        .get("content-length")
                        .unwrap()
                        .parse::<usize>()
                        .unwrap();

                    // Read and verify the body
                    let body = read_body(&mut stream, content_length).await.unwrap();
                    assert!(body.contains("test_counter_total 1"));
                });

            // Wait for the client task to complete
            client_handle.await.unwrap();
        });
    }
}
