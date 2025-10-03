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

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::select;
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
mod process;
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
    ///
    /// When this function returns, all spawned tasks will be canceled. If clean
    /// shutdown cannot be implemented via `Drop`, consider using [Spawner::stop] and
    /// [Spawner::stopped] to coordinate clean shutdown.
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
    /// If this function is used to spawn multiple tasks from the same context (including child
    /// tasks), the runtime will panic to prevent accidental misuse.
    ///
    /// `spawn_ref` installs a fresh child list for the new task. Clones created before the call keep
    /// pointing at the previous list, so children spawned from those clones run independently (they
    /// are not aborted when the parent finishes). If you want child supervision to apply, obtain the
    /// `spawn_ref` closure first and then clone/label inside the task:
    ///
    /// ```rust
    /// use commonware_runtime::{deterministic, Runner, Spawner};
    ///
    /// let executor = deterministic::Runner::default();
    /// executor.start(|mut context| async move {
    ///     context.spawn_ref()(async move {
    ///         context.clone().spawn_child(|_| async move { /* ... */ });
    ///     });
    /// });
    /// ```
    fn spawn_ref<F, T>(&mut self) -> impl FnOnce(F) -> Handle<T> + 'static
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static;

    /// Enqueue a child task to be executed that will be automatically aborted when the
    /// parent task completes or is aborted.
    ///
    /// The spawned task will be tracked as a child of the current task. When
    /// the parent task completes (either successfully or via abort), all child
    /// tasks will be automatically aborted.
    ///
    /// # Context cloning and children
    ///
    /// When a context is cloned (via `Clone::clone`) or a new context is created (via methods
    /// like `with_label`), you get another reference to the same context. However:
    /// - Tasks spawned with `spawn` from any context (original or cloned) are always independent
    /// - Only tasks spawned with `spawn_child` become children of the current task
    /// - Child tasks are tied to the task that spawned them, not to the context itself
    ///
    /// # Note
    ///
    /// Only async tasks can be spawned as children, since blocking tasks cannot be
    /// aborted and therefore can't support parent-child relationships.
    fn spawn_child<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
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

    /// Signals the runtime to stop execution and waits for all outstanding tasks
    /// to perform any required cleanup and exit.
    ///
    /// This method does not actually kill any tasks but rather signals to them, using
    /// the [signal::Signal] returned by [Spawner::stopped], that they should exit.
    /// It then waits for all [signal::Signal] references to be dropped before returning.
    ///
    /// ## Multiple Stop Calls
    ///
    /// This method is idempotent and safe to call multiple times concurrently (on
    /// different instances of the same context since it consumes `self`). The first
    /// call initiates shutdown with the provided `value`, and all subsequent calls
    /// will wait for the same completion regardless of their `value` parameter, i.e.
    /// the original `value` from the first call is preserved.
    ///
    /// ## Timeout
    ///
    /// If a timeout is provided, the method will return an error if all [signal::Signal]
    /// references have not been dropped within the specified duration.
    fn stop(
        self,
        value: i32,
        timeout: Option<Duration>,
    ) -> impl Future<Output = Result<(), Error>> + Send;

    /// Returns an instance of a [signal::Signal] that resolves when [Spawner::stop] is called by
    /// any task.
    ///
    /// If [Spawner::stop] has already been called, the [signal::Signal] returned will resolve
    /// immediately. The [signal::Signal] returned will always resolve to the value of the
    /// first [Spawner::stop] call.
    fn stopped(&self) -> signal::Signal;
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

    /// Await a future with a timeout, returning `Error::Timeout` if it expires.
    ///
    /// # Examples
    ///
    /// ```
    /// use std::time::Duration;
    /// use commonware_runtime::{deterministic, Error, Runner, Clock};
    ///
    /// let executor = deterministic::Runner::default();
    /// executor.start(|context| async move {
    ///     match context
    ///         .timeout(Duration::from_millis(100), async { 42 })
    ///         .await
    ///     {
    ///         Ok(value) => assert_eq!(value, 42),
    ///         Err(Error::Timeout) => panic!("should not timeout"),
    ///         Err(e) => panic!("unexpected error: {:?}", e),
    ///     }
    /// });
    /// ```
    fn timeout<F, T>(
        &self,
        duration: Duration,
        future: F,
    ) -> impl Future<Output = Result<T, Error>> + Send + '_
    where
        F: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        async move {
            select! {
                result = future => {
                    Ok(result)
                },
                _ = self.sleep(duration) => {
                    Err(Error::Timeout)
                },
            }
        }
    }
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
///
/// When a blob is dropped, any unsynced changes may be discarded. Implementations
/// may attempt to sync during drop but errors will go unhandled. Call `sync`
/// before dropping to ensure all changes are durably persisted.
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
}

#[cfg(test)]
mod tests {
    use super::*;
    use bytes::Bytes;
    use commonware_macros::select;
    use futures::{
        channel::{mpsc, oneshot},
        future::{pending, ready},
        join, pin_mut, FutureExt, SinkExt, StreamExt,
    };
    use prometheus_client::metrics::counter::Counter;
    use std::{
        collections::HashMap,
        panic::{catch_unwind, AssertUnwindSafe},
        pin::Pin,
        str::FromStr,
        sync::{
            atomic::{AtomicU32, Ordering},
            Arc, Mutex,
        },
        task::{Context as TContext, Poll, Waker},
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

    fn test_clock_timeout<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            // Future completes before timeout
            let result = context
                .timeout(Duration::from_millis(100), async { "success" })
                .await;
            assert_eq!(result.unwrap(), "success");

            // Future exceeds timeout duration
            let result = context
                .timeout(Duration::from_millis(50), pending::<()>())
                .await;
            assert!(matches!(result, Err(Error::Timeout)));

            // Future completes within timeout
            let result = context
                .timeout(
                    Duration::from_millis(100),
                    context.sleep(Duration::from_millis(50)),
                )
                .await;
            assert!(result.is_ok());
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

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

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

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

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

            // Re-open and check length
            let (blob, len) = context.open(partition, name).await.unwrap();
            assert_eq!(len, data.len() as u64);

            // Resize to extend the file
            let new_len = (data.len() as u64) * 2;
            blob.resize(new_len)
                .await
                .expect("Failed to resize to extend");
            blob.sync().await.expect("Failed to sync after resize");

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

            // Reopen to check truncation
            let (blob, size) = context.open(partition, name).await.unwrap();
            assert_eq!(size, data.len() as u64);

            // Read truncated data
            let read_buf = blob.read_at(vec![0; data.len()], 0).await.unwrap();
            assert_eq!(read_buf.as_ref(), data);
            blob.sync().await.unwrap();
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

                // Sync the blob
                blob.sync().await.expect("Failed to sync blob");
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

            // Drop the blob
            drop(blob);

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
                    let mut signal = context.stopped();
                    let value = (&mut signal).await.unwrap();
                    assert_eq!(value, kill);
                    drop(signal);
                });

            // Signal the tasks and wait for them to stop
            let result = context.clone().stop(kill, None).await;
            assert!(result.is_ok());

            // Spawn a task after stop is called
            let after = context
                .with_label("after")
                .spawn(move |context| async move {
                    // A call to `stopped()` after `stop()` resolves immediately
                    let value = context.stopped().await.unwrap();
                    assert_eq!(value, kill);
                });

            // Ensure both tasks complete
            let result = join!(before, after);
            assert!(result.0.is_ok());
            assert!(result.1.is_ok());
        });
    }

    fn test_shutdown_multiple_signals<R: Runner>(runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill = 42;
        runner.start(|context| async move {
            let (started_tx, mut started_rx) = mpsc::channel(3);
            let counter = Arc::new(AtomicU32::new(0));

            // Spawn 3 tasks that do cleanup work after receiving stop signal
            // and increment a shared counter
            let task = |cleanup_duration: Duration| {
                let context = context.clone();
                let counter = counter.clone();
                let mut started_tx = started_tx.clone();
                context.spawn(move |context| async move {
                    // Wait for signal to be acquired
                    let mut signal = context.stopped();
                    started_tx.send(()).await.unwrap();

                    // Increment once killed
                    let value = (&mut signal).await.unwrap();
                    assert_eq!(value, kill);
                    context.sleep(cleanup_duration).await;
                    counter.fetch_add(1, Ordering::SeqCst);

                    // Wait to drop signal until work has been done
                    drop(signal);
                })
            };

            let task1 = task(Duration::from_millis(10));
            let task2 = task(Duration::from_millis(20));
            let task3 = task(Duration::from_millis(30));

            // Give tasks time to start
            for _ in 0..3 {
                started_rx.next().await.unwrap();
            }

            // Stop and verify all cleanup completed
            context.stop(kill, None).await.unwrap();
            assert_eq!(counter.load(Ordering::SeqCst), 3);

            // Ensure all tasks completed
            let result = join!(task1, task2, task3);
            assert!(result.0.is_ok());
            assert!(result.1.is_ok());
            assert!(result.2.is_ok());
        });
    }

    fn test_shutdown_timeout<R: Runner>(runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill = 42;
        runner.start(|context| async move {
            // Setup startup coordinator
            let (started_tx, started_rx) = oneshot::channel();

            // Spawn a task that never completes its cleanup
            context.clone().spawn(move |context| async move {
                let signal = context.stopped();
                started_tx.send(()).unwrap();
                pending::<()>().await;
                signal.await.unwrap();
            });

            // Try to stop with a timeout
            started_rx.await.unwrap();
            let result = context.stop(kill, Some(Duration::from_millis(100))).await;

            // Assert that we got a timeout error
            assert!(matches!(result, Err(Error::Timeout)));
        });
    }

    fn test_shutdown_multiple_stop_calls<R: Runner>(runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill1 = 42;
        let kill2 = 43;

        runner.start(|context| async move {
            let (started_tx, started_rx) = oneshot::channel();
            let counter = Arc::new(AtomicU32::new(0));

            // Spawn a task that delays completion to test timing
            let task = context.with_label("blocking_task").spawn({
                let counter = counter.clone();
                move |context| async move {
                    // Wait for signal to be acquired
                    let mut signal = context.stopped();
                    started_tx.send(()).unwrap();

                    // Wait for signal to be resolved
                    let value = (&mut signal).await.unwrap();
                    assert_eq!(value, kill1);
                    context.sleep(Duration::from_millis(50)).await;

                    // Increment counter
                    counter.fetch_add(1, Ordering::SeqCst);
                    drop(signal);
                }
            });

            // Give task time to start
            started_rx.await.unwrap();

            // Issue two separate stop calls
            // The second stop call uses a different stop value that should be ignored
            let stop_task1 = context.clone().stop(kill1, None);
            pin_mut!(stop_task1);
            let stop_task2 = context.clone().stop(kill2, None);
            pin_mut!(stop_task2);

            // Both of them should be awaiting completion
            assert!(stop_task1.as_mut().now_or_never().is_none());
            assert!(stop_task2.as_mut().now_or_never().is_none());

            // Wait for both stop calls to complete
            assert!(stop_task1.await.is_ok());
            assert!(stop_task2.await.is_ok());

            // Verify first stop value wins
            let sig = context.stopped().await;
            assert_eq!(sig.unwrap(), kill1);

            // Wait for blocking task to complete
            let result = task.await;
            assert!(result.is_ok());
            assert_eq!(counter.load(Ordering::SeqCst), 1);

            // Post-completion stop should return immediately
            assert!(context.stop(kill2, None).now_or_never().unwrap().is_ok());
        });
    }

    fn test_unfulfilled_shutdown<R: Runner>(runner: R)
    where
        R::Context: Spawner + Metrics,
    {
        runner.start(|context| async move {
            // Spawn a task that waits for signal
            context
                .with_label("before")
                .spawn(move |context| async move {
                    let mut signal = context.stopped();
                    let value = (&mut signal).await.unwrap();

                    // We should never reach this point
                    assert_eq!(value, 42);
                    drop(signal);
                });

            // Ensure waker is registered
            reschedule().await;
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

    fn spawn_with<C, F, Fut, T>(context: &mut C, use_spawn_ref: bool, task: F) -> Handle<T>
    where
        C: Spawner,
        F: FnOnce(C) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
        T: Send + 'static,
    {
        if use_spawn_ref {
            let spawn = context.spawn_ref();
            let helper = context.clone();
            spawn(task(helper))
        } else {
            context.clone().spawn(task)
        }
    }

    fn test_spawn_child<R: Runner>(runner: R, use_spawn_ref: bool)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|mut context| async move {
            let child_handle = Arc::new(Mutex::new(None));
            let child_handle2 = child_handle.clone();

            let (parent_initialized_tx, parent_initialized_rx) = oneshot::channel();
            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();
            let parent_handle =
                spawn_with(&mut context, use_spawn_ref, move |context| async move {
                    // Spawn child that completes immediately
                    let handle = context.spawn_child(|_| async {});

                    // Store child handle so we can test it later
                    *child_handle2.lock().unwrap() = Some(handle);

                    parent_initialized_tx.send(()).unwrap();

                    // Parent task completes
                    parent_complete_rx.await.unwrap();
                });

            // Wait for parent task to spawn the children
            parent_initialized_rx.await.unwrap();

            // Child task completes successfully
            let child_handle = child_handle.lock().unwrap().take().unwrap();
            assert!(child_handle.await.is_ok());

            // Complete the parent task
            parent_complete_tx.send(()).unwrap();

            // Wait for parent task to complete successfully
            assert!(parent_handle.await.is_ok());
        });
    }

    fn test_spawn_child_abort_on_parent_abort<R: Runner>(runner: R, use_spawn_ref: bool)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|mut context| async move {
            let child_handle = Arc::new(Mutex::new(None));
            let child_handle2 = child_handle.clone();

            let (parent_initialized_tx, parent_initialized_rx) = oneshot::channel();
            let parent_handle =
                spawn_with(&mut context, use_spawn_ref, move |context| async move {
                    // Spawn child task that hangs forever, should be aborted when parent aborts
                    let handle = context.spawn_child(|_| pending::<()>());

                    // Store child task handle so we can test it later
                    *child_handle2.lock().unwrap() = Some(handle);

                    parent_initialized_tx.send(()).unwrap();

                    // Parent task runs until aborted
                    pending::<()>().await
                });

            // Wait for parent task to spawn the children
            parent_initialized_rx.await.unwrap();

            // Abort parent task
            parent_handle.abort();
            assert!(parent_handle.await.is_err());

            // Child task should also resolve with error since its parent aborted
            let child_handle = child_handle.lock().unwrap().take().unwrap();
            assert!(child_handle.await.is_err());
        });
    }

    fn test_spawn_child_abort_on_parent_completion<R: Runner>(runner: R, use_spawn_ref: bool)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|mut context| async move {
            let child_handle = Arc::new(Mutex::new(None));
            let child_handle2 = child_handle.clone();

            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();
            let parent_handle =
                spawn_with(&mut context, use_spawn_ref, move |context| async move {
                    // Spawn child task that hangs forever, should be aborted when parent completes
                    let handle = context.spawn_child(|_| pending::<()>());

                    // Store child task handle so we can test it later
                    *child_handle2.lock().unwrap() = Some(handle);

                    // Parent task completes
                    parent_complete_rx.await.unwrap();
                });

            // Fire parent completion
            parent_complete_tx.send(()).unwrap();

            // Wait for parent task to complete
            assert!(parent_handle.await.is_ok());

            // Child task should also resolve with error since its parent has completed
            let child_handle = child_handle.lock().unwrap().take().unwrap();
            assert!(child_handle.await.is_err());
        });
    }

    fn test_spawn_child_cascading_abort<R: Runner>(runner: R, use_spawn_ref: bool)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|mut context| async move {
            // We create the following tree of tasks. All tasks will run
            // indefinitely (until aborted).
            //
            //          root
            //     /     |     \
            //    /      |      \
            //   c0      c1      c2
            //  /  \    /  \    /  \
            // g0  g1  g2  g3  g4  g5

            let handles = Arc::new(Mutex::new(Vec::new()));
            let (mut initialized_tx, mut initialized_rx) = mpsc::channel(9);
            let root_task = {
                let handles = handles.clone();
                spawn_with(&mut context, use_spawn_ref, move |context| async move {
                    for _ in 0..3 {
                        let handles2 = handles.clone();
                        let mut initialized_tx2 = initialized_tx.clone();
                        let handle = context.clone().spawn_child(move |context| async move {
                            for _ in 0..2 {
                                let handle = context.clone().spawn_child(|_| async {
                                    pending::<()>().await;
                                });
                                handles2.lock().unwrap().push(handle);
                                initialized_tx2.send(()).await.unwrap();
                            }
                            pending::<()>().await;
                        });

                        handles.lock().unwrap().push(handle);
                        initialized_tx.send(()).await.unwrap();
                    }

                    pending::<()>().await;
                })
            };

            // Wait for tasks to initialize
            for _ in 0..9 {
                initialized_rx.next().await.unwrap();
            }

            // Verify we have all 9 handles (3 children + 6 grandchildren)
            assert_eq!(handles.lock().unwrap().len(), 9,);

            // Abort root task
            root_task.abort();
            assert!(root_task.await.is_err());

            // All handles should resolve with error due to cascading abort
            let handles = handles.lock().unwrap().drain(..).collect::<Vec<_>>();
            for handle in handles {
                assert!(handle.await.is_err());
            }
        });
    }

    fn test_child_survives_sibling_completion<R: Runner>(runner: R, use_spawn_ref: bool)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (child_started_tx, child_started_rx) = oneshot::channel();
            let (child_complete_tx, child_complete_rx) = oneshot::channel();
            let (sibling_started_tx, sibling_started_rx) = oneshot::channel();
            let (sibling_complete_tx, sibling_complete_rx) = oneshot::channel();
            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();

            let parent = context.spawn(move |mut context| async move {
                // Spawn a child task
                context.clone().spawn_child(|_| async move {
                    child_started_tx.send(()).unwrap();
                    // Wait for signal to complete
                    child_complete_rx.await.unwrap();
                });

                // Spawn an independent sibling task using spawn or spawn_ref based on parameter
                spawn_with(&mut context, use_spawn_ref, |_| async move {
                    sibling_started_tx.send(()).unwrap();
                    // Wait for signal to complete
                    sibling_complete_rx.await.unwrap();
                });

                // Wait for signal to complete
                parent_complete_rx.await.unwrap();
            });

            // Wait for both to start
            child_started_rx.await.unwrap();
            sibling_started_rx.await.unwrap();

            // Kill the sibling
            sibling_complete_tx.send(()).unwrap();

            // The child task should still be alive
            child_complete_tx.send(()).unwrap();

            // As well as the parent
            parent_complete_tx.send(()).unwrap();

            assert!(parent.await.is_ok());
        });
    }

    fn test_clone_context_no_child_inheritance<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (child_started_tx, child_started_rx) = oneshot::channel();
            let (child_complete_tx, child_complete_rx) = oneshot::channel();
            let (cloned_task_started_tx, cloned_task_started_rx) = oneshot::channel();
            let (cloned_task_complete_tx, cloned_task_complete_rx) = oneshot::channel();
            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();

            // Parent task that spawns a child using a cloned context
            let cloned_context = context.clone();
            let parent = cloned_context.spawn(move |context| async move {
                // Spawn a child task
                context.spawn_child(|_| async move {
                    child_started_tx.send(()).unwrap();
                    child_complete_rx.await.unwrap();
                });

                // Wait for parent to complete
                parent_complete_rx.await.unwrap();
            });

            // Use the original context that was previously cloned and spawn a
            // task. This task should NOT inherit the child relationship
            context.spawn(move |_| async move {
                cloned_task_started_tx.send(()).unwrap();
                cloned_task_complete_rx.await.unwrap();
            });

            // Wait for both tasks to start
            child_started_rx.await.unwrap();
            cloned_task_started_rx.await.unwrap();

            // Complete the cloned task, this should NOT affect the child in the
            // other context
            cloned_task_complete_tx.send(()).unwrap();

            // The child should still be alive
            child_complete_tx.send(()).unwrap();

            // As well as the parent
            parent_complete_tx.send(()).unwrap();

            assert!(parent.await.is_ok());
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

    fn test_spawn_blocking_panic<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let handle = context.spawn_blocking(dedicated, |_| {
                panic!("blocking task panicked");
            });
            handle.await.unwrap_err();
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

    fn test_circular_reference_prevents_cleanup<R: Runner>(runner: R) {
        runner.start(|_| async move {
            // Setup tracked resource
            let dropper = Arc::new(());
            let executor = deterministic::Runner::default();
            executor.start({
                let dropper = dropper.clone();
                move |context| async move {
                    // Create tasks with circular dependencies through channels
                    let (mut setup_tx, mut setup_rx) = mpsc::unbounded::<()>();
                    let (mut tx1, mut rx1) = mpsc::unbounded::<()>();
                    let (mut tx2, mut rx2) = mpsc::unbounded::<()>();

                    // Task 1 holds tx2 and waits on rx1
                    context.with_label("task1").spawn({
                        let mut setup_tx = setup_tx.clone();
                        let dropper = dropper.clone();
                        move |_| async move {
                            // Setup deadlock and mark ready
                            tx2.send(()).await.unwrap();
                            rx1.next().await.unwrap();
                            setup_tx.send(()).await.unwrap();

                            // Wait forever
                            while rx1.next().await.is_some() {}
                            drop(tx2);
                            drop(dropper);
                        }
                    });

                    // Task 2 holds tx1 and waits on rx2
                    context.with_label("task2").spawn(move |_| async move {
                        // Setup deadlock and mark ready
                        tx1.send(()).await.unwrap();
                        rx2.next().await.unwrap();
                        setup_tx.send(()).await.unwrap();

                        // Wait forever
                        while rx2.next().await.is_some() {}
                        drop(tx1);
                        drop(dropper);
                    });

                    // Wait for tasks to start
                    setup_rx.next().await.unwrap();
                    setup_rx.next().await.unwrap();
                }
            });

            // After runtime drop, both tasks should be cleaned up
            Arc::try_unwrap(dropper).expect("references remaining");
        });
    }

    fn test_late_waker<R: Runner>(runner: R)
    where
        R::Context: Metrics + Spawner,
    {
        // A future that captures its waker and sends it to the caller, then
        // stays pending forever.
        struct CaptureWaker {
            tx: Option<oneshot::Sender<Waker>>,
            sent: bool,
        }
        impl Future for CaptureWaker {
            type Output = ();
            fn poll(mut self: Pin<&mut Self>, cx: &mut TContext<'_>) -> Poll<Self::Output> {
                if !self.sent {
                    if let Some(tx) = self.tx.take() {
                        // Send a clone of the current task's waker to the root
                        let _ = tx.send(cx.waker().clone());
                    }
                    self.sent = true;
                }
                Poll::Pending
            }
        }

        // A guard that wakes the captured waker on drop.
        struct WakeOnDrop(Option<Waker>);
        impl Drop for WakeOnDrop {
            fn drop(&mut self) {
                if let Some(w) = self.0.take() {
                    w.wake_by_ref();
                }
            }
        }

        // Run the executor to completion
        let holder = runner.start(|context| async move {
            // Wire a oneshot to receive the task waker.
            let (tx, rx) = oneshot::channel::<Waker>();

            // Spawn a task that registers its waker and then stays pending.
            context
                .with_label("capture-waker")
                .spawn(move |_| async move {
                    CaptureWaker {
                        tx: Some(tx),
                        sent: false,
                    }
                    .await;
                });

            // Ensure the spawned task runs and registers its waker.
            utils::reschedule().await;

            // Receive the waker from the spawned task.
            let waker = rx.await.expect("waker not received");

            // Return a guard that will wake after the runtime has dropped.
            WakeOnDrop(Some(waker))
        });

        // Dropping the guard after the runtime has torn down will trigger a wake on
        // a task whose executor has been dropped.
        drop(holder);
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
    fn test_deterministic_clock_timeout() {
        let executor = deterministic::Runner::default();
        test_clock_timeout(executor);
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
    #[should_panic(expected = "task panicked: blah")]
    fn test_deterministic_panic_aborts_spawn() {
        let executor = deterministic::Runner::default();
        test_panic_aborts_spawn(executor);
    }

    #[test]
    fn test_deterministic_panic_aborts_spawn_caught() {
        let cfg = deterministic::Config::default().with_catch_panics(true);
        let executor = deterministic::Runner::new(cfg);
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
    fn test_deterministic_shutdown_multiple_signals() {
        let executor = deterministic::Runner::default();
        test_shutdown_multiple_signals(executor);
    }

    #[test]
    fn test_deterministic_shutdown_timeout() {
        let executor = deterministic::Runner::default();
        test_shutdown_timeout(executor);
    }

    #[test]
    fn test_deterministic_shutdown_multiple_stop_calls() {
        let executor = deterministic::Runner::default();
        test_shutdown_multiple_stop_calls(executor);
    }

    #[test]
    fn test_deterministic_unfulfilled_shutdown() {
        let executor = deterministic::Runner::default();
        test_unfulfilled_shutdown(executor);
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
    fn test_deterministic_spawn_child() {
        for use_spawn_ref in [false, true] {
            let runner = deterministic::Runner::default();
            test_spawn_child(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_deterministic_spawn_child_abort_on_parent_abort() {
        for use_spawn_ref in [false, true] {
            let runner = deterministic::Runner::default();
            test_spawn_child_abort_on_parent_abort(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_deterministic_spawn_child_abort_on_parent_completion() {
        for use_spawn_ref in [false, true] {
            let runner = deterministic::Runner::default();
            test_spawn_child_abort_on_parent_completion(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_deterministic_spawn_child_cascading_abort() {
        for use_spawn_ref in [false, true] {
            let runner = deterministic::Runner::default();
            test_spawn_child_cascading_abort(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_deterministic_child_survives_sibling_completion() {
        for use_spawn_ref in [false, true] {
            let runner = deterministic::Runner::default();
            test_child_survives_sibling_completion(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_deterministic_clone_context_no_child_inheritance() {
        let runner = deterministic::Runner::default();
        test_clone_context_no_child_inheritance(runner);
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
            test_spawn_blocking_panic(executor, dedicated);
        }
    }

    #[test]
    fn test_deterministic_spawn_blocking_panic_caught() {
        for dedicated in [false, true] {
            let cfg = deterministic::Config::default().with_catch_panics(true);
            let executor = deterministic::Runner::new(cfg);
            test_spawn_blocking_panic(executor, dedicated);
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
    fn test_deterministic_circular_reference_prevents_cleanup() {
        let executor = deterministic::Runner::default();
        test_circular_reference_prevents_cleanup(executor);
    }

    #[test]
    fn test_deterministic_late_waker() {
        let executor = deterministic::Runner::default();
        test_late_waker(executor);
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
    fn test_tokio_clock_timeout() {
        let executor = tokio::Runner::default();
        test_clock_timeout(executor);
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
    #[should_panic(expected = "task panicked: blah")]
    fn test_tokio_panic_aborts_spawn() {
        let executor = tokio::Runner::default();
        test_panic_aborts_spawn(executor);
    }

    #[test]
    fn test_tokio_panic_aborts_spawn_caught() {
        let cfg = tokio::Config::default().with_catch_panics(true);
        let executor = tokio::Runner::new(cfg);
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
    fn test_tokio_shutdown_multiple_signals() {
        let executor = tokio::Runner::default();
        test_shutdown_multiple_signals(executor);
    }

    #[test]
    fn test_tokio_shutdown_timeout() {
        let executor = tokio::Runner::default();
        test_shutdown_timeout(executor);
    }

    #[test]
    fn test_tokio_shutdown_multiple_stop_calls() {
        let executor = tokio::Runner::default();
        test_shutdown_multiple_stop_calls(executor);
    }

    #[test]
    fn test_tokio_unfulfilled_shutdown() {
        let executor = tokio::Runner::default();
        test_unfulfilled_shutdown(executor);
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
    fn test_tokio_spawn_child() {
        for use_spawn_ref in [false, true] {
            let runner = tokio::Runner::default();
            test_spawn_child(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_tokio_spawn_child_abort_on_parent_abort() {
        for use_spawn_ref in [false, true] {
            let runner = tokio::Runner::default();
            test_spawn_child_abort_on_parent_abort(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_tokio_spawn_child_abort_on_parent_completion() {
        for use_spawn_ref in [false, true] {
            let runner = tokio::Runner::default();
            test_spawn_child_abort_on_parent_completion(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_tokio_spawn_child_cascading_abort() {
        for use_spawn_ref in [false, true] {
            let runner = tokio::Runner::default();
            test_spawn_child_cascading_abort(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_tokio_child_survives_sibling_completion() {
        for use_spawn_ref in [false, true] {
            let runner = tokio::Runner::default();
            test_child_survives_sibling_completion(runner, use_spawn_ref);
        }
    }

    #[test]
    fn test_tokio_clone_context_no_child_inheritance() {
        let runner = tokio::Runner::default();
        test_clone_context_no_child_inheritance(runner);
    }

    #[test]
    fn test_tokio_spawn_blocking() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            test_spawn_blocking(executor, dedicated);
        }
    }

    #[test]
    #[should_panic(expected = "blocking task panicked")]
    fn test_tokio_spawn_blocking_panic() {
        for dedicated in [false, true] {
            let executor = tokio::Runner::default();
            test_spawn_blocking_panic(executor, dedicated);
        }
    }

    #[test]
    fn test_tokio_spawn_blocking_panic_caught() {
        for dedicated in [false, true] {
            let cfg = tokio::Config::default().with_catch_panics(true);
            let executor = tokio::Runner::new(cfg);
            test_spawn_blocking_panic(executor, dedicated);
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
    fn test_tokio_circular_reference_prevents_cleanup() {
        let executor = tokio::Runner::default();
        test_circular_reference_prevents_cleanup(executor);
    }

    #[test]
    fn test_tokio_late_waker() {
        let executor = tokio::Runner::default();
        test_late_waker(executor);
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
    fn test_tokio_process_rss_metric() {
        let executor = tokio::Runner::default();
        executor.start(|context| async move {
            loop {
                // Wait for RSS metric to be available
                let metrics = context.encode();
                if !metrics.contains("runtime_process_rss") {
                    context.sleep(Duration::from_millis(100)).await;
                    continue;
                }

                // Verify the RSS value is eventually populated (greater than 0)
                for line in metrics.lines() {
                    if line.starts_with("runtime_process_rss")
                        && !line.starts_with("runtime_process_rss{")
                    {
                        let parts: Vec<&str> = line.split_whitespace().collect();
                        if parts.len() >= 2 {
                            let rss_value: i64 =
                                parts[1].parse().expect("Failed to parse RSS value");
                            if rss_value > 0 {
                                return;
                            }
                        }
                    }
                }
            }
        });
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
