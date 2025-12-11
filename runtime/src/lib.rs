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
    #[error("partition name invalid, must only contain alphanumeric, dash ('-'), or underscore ('_') characters: {0}")]
    PartitionNameInvalid(String),
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
    /// Return a [`Spawner`] that schedules tasks onto the runtime's shared executor.
    ///
    /// Set `blocking` to `true` when the task may hold the thread for a short, blocking operation.
    /// Runtimes can use this hint to move the work to a blocking-friendly pool so asynchronous
    /// tasks on a work-stealing executor are not starved. For long-lived, blocking work, use
    /// [`Spawner::dedicated`] instead.
    ///
    /// The shared executor with `blocking == false` is the default spawn mode.
    fn shared(self, blocking: bool) -> Self;

    /// Return a [`Spawner`] that runs tasks on a dedicated thread when the runtime supports it.
    ///
    /// Reserve this for long-lived or prioritized tasks that should not compete for resources in the
    /// shared executor.
    ///
    /// This is not the default behavior. See [`Spawner::shared`] for more information.
    fn dedicated(self) -> Self;

    /// Return a [`Spawner`] that instruments the next spawned task with the label of the spawning context.
    fn instrumented(self) -> Self;

    /// Spawn a task with the current context.
    ///
    /// Unlike directly awaiting a future, the task starts running immediately even if the caller
    /// never awaits the returned [`Handle`].
    ///
    /// # Mandatory Supervision
    ///
    /// All tasks are supervised. When a parent task finishes or is aborted, all its descendants are aborted.
    ///
    /// Spawn consumes the current task and provides a new child context to the spawned task. Likewise, cloning
    /// a context (either via [`Clone::clone`] or [`Metrics::with_label`]) returns a child context.
    ///
    /// ```txt
    /// ctx_a
    ///   |
    ///   +-- clone() ---> ctx_c
    ///   |                  |
    ///   |                  +-- spawn() ---> Task C (ctx_d)
    ///   |
    ///   +-- spawn() ---> Task A (ctx_b)
    ///                              |
    ///                              +-- spawn() ---> Task B (ctx_e)
    ///
    /// Task A finishes or aborts --> Task B and Task C are aborted
    /// ```
    ///
    /// # Spawn Configuration
    ///
    /// When a context is cloned (either via [`Clone::clone`] or [`Metrics::with_label`]) or provided via
    /// [`Spawner::spawn`], any configuration made via [`Spawner::dedicated`] or [`Spawner::shared`] is reset.
    ///
    /// Child tasks should assume they start from a clean configuration without needing to inspect how their
    /// parent was configured.
    fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
    where
        F: FnOnce(Self) -> Fut + Send + 'static,
        Fut: Future<Output = T> + Send + 'static,
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

cfg_if::cfg_if! {
    if #[cfg(feature = "external")] {
        /// Interface that runtimes can implement to constrain the execution latency of a future.
        pub trait Pacer: Clock + Clone + Send + Sync + 'static {
            /// Defer completion of a future until a specified `latency` has elapsed. If the future is
            /// not yet ready at the desired time of completion, the runtime will block until the future
            /// is ready.
            ///
            /// In [crate::deterministic], this is used to ensure interactions with external systems can
            /// be interacted with deterministically. In [crate::tokio], this is a no-op (allows
            /// multiple runtimes to be tested with no code changes).
            ///
            /// # Setting Latency
            ///
            /// `pace` is not meant to be a time penalty applied to awaited futures and should be set to
            /// the expected resolution latency of the future. To better explore the possible behavior of an
            /// application, users can set latency to a randomly chosen value in the range of
            /// `[expected latency / 2, expected latency * 2]`.
            ///
            /// # Warning
            ///
            /// Because `pace` blocks if the future is not ready, it is important that the future's completion
            /// doesn't require anything in the current thread to complete (or else it will deadlock).
            fn pace<'a, F, T>(
                &'a self,
                latency: Duration,
                future: F,
            ) -> impl Future<Output = T> + Send + 'a
            where
                F: Future<Output = T> + Send + 'a,
                T: Send + 'a;
        }

        /// Extension trait that makes it more ergonomic to use [Pacer].
        ///
        /// This inverts the call-site of [`Pacer::pace`] by letting the future itself request how the
        /// runtime should delay completion relative to the clock.
        pub trait FutureExt: Future + Send + Sized {
            /// Delay completion of the future until a specified `latency` on `pacer`.
            fn pace<'a, E>(
                self,
                pacer: &'a E,
                latency: Duration,
            ) -> impl Future<Output = Self::Output> + Send + 'a
            where
                E: Pacer + 'a,
                Self: Send + 'a,
                Self::Output: Send + 'a,
            {
                pacer.pace(latency, self)
            }
        }

        impl<F> FutureExt for F where F: Future + Send {}
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
/// To support storage implementations that enable concurrent reads and
/// writes, blobs are responsible for maintaining synchronization.
///
/// Storage can be backed by a local filesystem, cloud storage, etc.
///
/// # Partition Names
///
/// Partition names must be non-empty and contain only ASCII alphanumeric
/// characters, dashes (`-`), or underscores (`_`). Names containing other
/// characters (e.g., `/`, `.`, spaces) will return an error.
pub trait Storage: Clone + Send + Sync + 'static {
    /// The readable/writeable storage buffer that can be opened by this Storage.
    type Blob: Blob;

    /// Open an existing blob in a given partition or create a new one, returning
    /// the blob and its length.
    ///
    /// Multiple instances of the same blob can be opened concurrently, however,
    /// writing to the same blob concurrently may lead to undefined behavior.
    ///
    /// An Ok result indicates the blob is durably created (or already exists).
    fn open(
        &self,
        partition: &str,
        name: &[u8],
    ) -> impl Future<Output = Result<(Self::Blob, u64), Error>> + Send;

    /// Remove a blob from a given partition.
    ///
    /// If no `name` is provided, the entire partition is removed.
    ///
    /// An Ok result indicates the blob is durably removed.
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
    use crate::telemetry::traces::collector::TraceStorage;
    use bytes::Bytes;
    use commonware_macros::{select, test_collect_traces};
    use futures::{
        channel::{mpsc, oneshot},
        future::{pending, ready},
        join, pin_mut, FutureExt, SinkExt, StreamExt,
    };
    use prometheus_client::metrics::counter::Counter;
    use std::{
        collections::HashMap,
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
        R::Context: Spawner + Clock + Metrics,
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

    fn test_spawn_after_abort<R>(runner: R)
    where
        R: Runner,
        R::Context: Spawner + Clone,
    {
        runner.start(|context| async move {
            // Create a child context
            let child = context.clone();

            // Spawn parent and abort
            let parent_handle = context.spawn(move |_| async move {
                pending::<()>().await;
            });
            parent_handle.abort();

            // Spawn child and ensure it aborts
            let child_handle = child.spawn(move |_| async move {
                pending::<()>().await;
            });
            assert!(matches!(child_handle.await, Err(Error::Closed)));
        });
    }

    fn test_spawn_abort<R: Runner>(runner: R, dedicated: bool, blocking: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let context = if dedicated {
                assert!(!blocking);
                context.dedicated()
            } else {
                context.shared(blocking)
            };

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
        let result: Result<(), Error> = runner.start(|_| async move {
            panic!("blah");
        });
        result.unwrap_err();
    }

    fn test_panic_aborts_spawn<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            context.clone().spawn(|_| async move {
                panic!("blah");
            });

            // Loop until panic
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    fn test_panic_aborts_spawn_caught<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        let result: Result<(), Error> = runner.start(|context| async move {
            let result = context.clone().spawn(|_| async move {
                panic!("blah");
            });
            result.await
        });
        assert!(matches!(result, Err(Error::Exited)));
    }

    fn test_multiple_panics<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            context.clone().spawn(|_| async move {
                panic!("boom 1");
            });
            context.clone().spawn(|_| async move {
                panic!("boom 2");
            });
            context.clone().spawn(|_| async move {
                panic!("boom 3");
            });

            // Loop until panic
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    fn test_multiple_panics_caught<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        let (res1, res2, res3) = runner.start(|context| async move {
            let handle1 = context.clone().spawn(|_| async move {
                panic!("boom 1");
            });
            let handle2 = context.clone().spawn(|_| async move {
                panic!("boom 2");
            });
            let handle3 = context.clone().spawn(|_| async move {
                panic!("boom 3");
            });

            join!(handle1, handle2, handle3)
        });
        assert!(matches!(res1, Err(Error::Exited)));
        assert!(matches!(res2, Err(Error::Exited)));
        assert!(matches!(res3, Err(Error::Exited)));
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

    fn test_spawn_dedicated<R: Runner>(runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let handle = context.dedicated().spawn(|_| async move { 42 });
            assert!(matches!(handle.await, Ok(42)));
        });
    }

    fn test_spawn<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let child_handle = Arc::new(Mutex::new(None));
            let child_handle2 = child_handle.clone();

            let (parent_initialized_tx, parent_initialized_rx) = oneshot::channel();
            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();
            let parent_handle = context.spawn(move |context| async move {
                // Spawn child that completes immediately
                let handle = context.spawn(|_| async {});

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

    fn test_spawn_abort_on_parent_abort<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let child_handle = Arc::new(Mutex::new(None));
            let child_handle2 = child_handle.clone();

            let (parent_initialized_tx, parent_initialized_rx) = oneshot::channel();
            let parent_handle = context.spawn(move |context| async move {
                // Spawn child task that hangs forever, should be aborted when parent aborts
                let handle = context.spawn(|_| pending::<()>());

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
            assert!(matches!(parent_handle.await, Err(Error::Closed)));

            // Child task should also resolve with error since its parent aborted
            let child_handle = child_handle.lock().unwrap().take().unwrap();
            assert!(matches!(child_handle.await, Err(Error::Closed)));
        });
    }

    fn test_spawn_abort_on_parent_completion<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let child_handle = Arc::new(Mutex::new(None));
            let child_handle2 = child_handle.clone();

            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();
            let parent_handle = context.spawn(move |context| async move {
                // Spawn child task that hangs forever, should be aborted when parent completes
                let handle = context.spawn(|_| pending::<()>());

                // Store child task handle so we can test it later
                *child_handle2.lock().unwrap() = Some(handle);

                // Parent task completes
                parent_complete_rx.await.unwrap();
            });

            // Fire parent completion
            parent_complete_tx.send(()).unwrap();

            // Wait for parent task to complete
            assert!(parent_handle.await.is_ok());

            // Child task should resolve with error since its parent has completed
            let child_handle = child_handle.lock().unwrap().take().unwrap();
            assert!(matches!(child_handle.await, Err(Error::Closed)));
        });
    }

    fn test_spawn_cascading_abort<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            // We create the following tree of tasks. All tasks will run
            // indefinitely (until aborted).
            //
            //          root
            //     /     |     \
            //    /      |      \
            //   c0      c1      c2
            //  /  \    /  \    /  \
            // g0  g1  g2  g3  g4  g5
            let c0 = context.clone();
            let g0 = c0.clone();
            let g1 = c0.clone();
            let c1 = context.clone();
            let g2 = c1.clone();
            let g3 = c1.clone();
            let c2 = context.clone();
            let g4 = c2.clone();
            let g5 = c2.clone();

            // Spawn tasks
            let handles = Arc::new(Mutex::new(Vec::new()));
            let (mut initialized_tx, mut initialized_rx) = mpsc::channel(9);
            let root_task = context.spawn({
                let handles = handles.clone();
                move |_| async move {
                    for (context, grandchildren) in [(c0, [g0, g1]), (c1, [g2, g3]), (c2, [g4, g5])]
                    {
                        let handle = context.spawn({
                            let handles = handles.clone();
                            let mut initialized_tx = initialized_tx.clone();
                            move |_| async move {
                                for grandchild in grandchildren {
                                    let handle = grandchild.spawn(|_| async {
                                        pending::<()>().await;
                                    });
                                    handles.lock().unwrap().push(handle);
                                    initialized_tx.send(()).await.unwrap();
                                }

                                pending::<()>().await;
                            }
                        });
                        handles.lock().unwrap().push(handle);
                        initialized_tx.send(()).await.unwrap();
                    }

                    pending::<()>().await;
                }
            });

            // Wait for tasks to initialize
            for _ in 0..9 {
                initialized_rx.next().await.unwrap();
            }

            // Verify we have all 9 handles (3 children + 6 grandchildren)
            assert_eq!(handles.lock().unwrap().len(), 9);

            // Abort root task
            root_task.abort();
            assert!(matches!(root_task.await, Err(Error::Closed)));

            // All handles should resolve with error due to cascading abort
            let handles = handles.lock().unwrap().drain(..).collect::<Vec<_>>();
            for handle in handles {
                assert!(matches!(handle.await, Err(Error::Closed)));
            }
        });
    }

    fn test_child_survives_sibling_completion<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (child_started_tx, child_started_rx) = oneshot::channel();
            let (child_complete_tx, child_complete_rx) = oneshot::channel();
            let (child_handle_tx, child_handle_rx) = oneshot::channel();
            let (sibling_started_tx, sibling_started_rx) = oneshot::channel();
            let (sibling_complete_tx, sibling_complete_rx) = oneshot::channel();
            let (sibling_handle_tx, sibling_handle_rx) = oneshot::channel();
            let (parent_complete_tx, parent_complete_rx) = oneshot::channel();

            let parent = context.spawn(move |context| async move {
                // Spawn a child task
                let child_handle = context.clone().spawn(|_| async move {
                    child_started_tx.send(()).unwrap();
                    // Wait for signal to complete
                    child_complete_rx.await.unwrap();
                });
                assert!(
                    child_handle_tx.send(child_handle).is_ok(),
                    "child handle receiver dropped"
                );

                // Spawn an independent sibling task
                let sibling_handle = context.clone().spawn(move |_| async move {
                    sibling_started_tx.send(()).unwrap();
                    // Wait for signal to complete
                    sibling_complete_rx.await.unwrap();
                });
                assert!(
                    sibling_handle_tx.send(sibling_handle).is_ok(),
                    "sibling handle receiver dropped"
                );

                // Wait for signal to complete
                parent_complete_rx.await.unwrap();
            });

            // Wait for both to start
            child_started_rx.await.unwrap();
            sibling_started_rx.await.unwrap();

            // Kill the sibling
            sibling_complete_tx.send(()).unwrap();
            assert!(sibling_handle_rx.await.is_ok());

            // The child task should still be alive
            child_complete_tx.send(()).unwrap();
            assert!(child_handle_rx.await.is_ok());

            // As well as the parent
            parent_complete_tx.send(()).unwrap();
            assert!(parent.await.is_ok());
        });
    }

    fn test_spawn_clone_chain<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (parent_started_tx, parent_started_rx) = oneshot::channel();
            let (child_started_tx, child_started_rx) = oneshot::channel();
            let (grandchild_started_tx, grandchild_started_rx) = oneshot::channel();
            let (child_handle_tx, child_handle_rx) = oneshot::channel();
            let (grandchild_handle_tx, grandchild_handle_rx) = oneshot::channel();

            let parent = context.clone().spawn({
                move |context| async move {
                    let child = context.clone().spawn({
                        move |context| async move {
                            let grandchild = context.clone().spawn({
                                move |_| async move {
                                    grandchild_started_tx.send(()).unwrap();
                                    pending::<()>().await;
                                }
                            });
                            assert!(
                                grandchild_handle_tx.send(grandchild).is_ok(),
                                "grandchild handle receiver dropped"
                            );
                            child_started_tx.send(()).unwrap();
                            pending::<()>().await;
                        }
                    });
                    assert!(
                        child_handle_tx.send(child).is_ok(),
                        "child handle receiver dropped"
                    );
                    parent_started_tx.send(()).unwrap();
                    pending::<()>().await;
                }
            });

            parent_started_rx.await.unwrap();
            child_started_rx.await.unwrap();
            grandchild_started_rx.await.unwrap();

            let child_handle = child_handle_rx.await.unwrap();
            let grandchild_handle = grandchild_handle_rx.await.unwrap();

            parent.abort();
            assert!(parent.await.is_err());

            assert!(child_handle.await.is_err());
            assert!(grandchild_handle.await.is_err());
        });
    }

    fn test_spawn_sparse_clone_chain<R: Runner>(runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (leaf_started_tx, leaf_started_rx) = oneshot::channel();
            let (leaf_handle_tx, leaf_handle_rx) = oneshot::channel();

            let parent = context.clone().spawn({
                move |context| async move {
                    let clone1 = context.clone();
                    let clone2 = clone1.clone();
                    let clone3 = clone2.clone();

                    let leaf = clone3.clone().spawn({
                        move |_| async move {
                            leaf_started_tx.send(()).unwrap();
                            pending::<()>().await;
                        }
                    });

                    leaf_handle_tx
                        .send(leaf)
                        .unwrap_or_else(|_| panic!("leaf handle receiver dropped"));
                    pending::<()>().await;
                }
            });

            leaf_started_rx.await.unwrap();
            let leaf_handle = leaf_handle_rx.await.unwrap();

            parent.abort();
            assert!(parent.await.is_err());
            assert!(leaf_handle.await.is_err());
        });
    }

    fn test_spawn_blocking<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let context = if dedicated {
                context.dedicated()
            } else {
                context.shared(true)
            };

            let handle = context.spawn(|_| async move { 42 });
            let result = handle.await;
            assert!(matches!(result, Ok(42)));
        });
    }

    fn test_spawn_blocking_panic<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let context = if dedicated {
                context.dedicated()
            } else {
                context.shared(true)
            };

            context.clone().spawn(|_| async move {
                panic!("blocking task panicked");
            });

            // Loop until panic
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    fn test_spawn_blocking_panic_caught<R: Runner>(runner: R, dedicated: bool)
    where
        R::Context: Spawner + Clock,
    {
        let result: Result<(), Error> = runner.start(|context| async move {
            let context = if dedicated {
                context.dedicated()
            } else {
                context.shared(true)
            };

            let handle = context.clone().spawn(|_| async move {
                panic!("blocking task panicked");
            });
            handle.await
        });
        assert!(matches!(result, Err(Error::Exited)));
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
    fn test_deterministic_spawn_after_abort() {
        let executor = deterministic::Runner::default();
        test_spawn_after_abort(executor);
    }

    #[test]
    fn test_deterministic_spawn_abort() {
        let executor = deterministic::Runner::default();
        test_spawn_abort(executor, false, false);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_deterministic_panic_aborts_root() {
        let runner = deterministic::Runner::default();
        test_panic_aborts_root(runner);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_deterministic_panic_aborts_root_caught() {
        let cfg = deterministic::Config::default().with_catch_panics(true);
        let runner = deterministic::Runner::new(cfg);
        test_panic_aborts_root(runner);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_deterministic_panic_aborts_spawn() {
        let executor = deterministic::Runner::default();
        test_panic_aborts_spawn(executor);
    }

    #[test]
    fn test_deterministic_panic_aborts_spawn_caught() {
        let cfg = deterministic::Config::default().with_catch_panics(true);
        let executor = deterministic::Runner::new(cfg);
        test_panic_aborts_spawn_caught(executor);
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn test_deterministic_multiple_panics() {
        let executor = deterministic::Runner::default();
        test_multiple_panics(executor);
    }

    #[test]
    fn test_deterministic_multiple_panics_caught() {
        let cfg = deterministic::Config::default().with_catch_panics(true);
        let executor = deterministic::Runner::new(cfg);
        test_multiple_panics_caught(executor);
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
    fn test_deterministic_spawn_dedicated() {
        let executor = deterministic::Runner::default();
        test_spawn_dedicated(executor);
    }

    #[test]
    fn test_deterministic_spawn() {
        let runner = deterministic::Runner::default();
        test_spawn(runner);
    }

    #[test]
    fn test_deterministic_spawn_abort_on_parent_abort() {
        let runner = deterministic::Runner::default();
        test_spawn_abort_on_parent_abort(runner);
    }

    #[test]
    fn test_deterministic_spawn_abort_on_parent_completion() {
        let runner = deterministic::Runner::default();
        test_spawn_abort_on_parent_completion(runner);
    }

    #[test]
    fn test_deterministic_spawn_cascading_abort() {
        let runner = deterministic::Runner::default();
        test_spawn_cascading_abort(runner);
    }

    #[test]
    fn test_deterministic_child_survives_sibling_completion() {
        let runner = deterministic::Runner::default();
        test_child_survives_sibling_completion(runner);
    }

    #[test]
    fn test_deterministic_spawn_clone_chain() {
        let runner = deterministic::Runner::default();
        test_spawn_clone_chain(runner);
    }

    #[test]
    fn test_deterministic_spawn_sparse_clone_chain() {
        let runner = deterministic::Runner::default();
        test_spawn_sparse_clone_chain(runner);
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
            test_spawn_blocking_panic_caught(executor, dedicated);
        }
    }

    #[test]
    fn test_deterministic_spawn_blocking_abort() {
        for (dedicated, blocking) in [(false, true), (true, false)] {
            let executor = deterministic::Runner::default();
            test_spawn_abort(executor, dedicated, blocking);
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
    fn test_tokio_spawn_after_abort() {
        let executor = tokio::Runner::default();
        test_spawn_after_abort(executor);
    }

    #[test]
    fn test_tokio_spawn_abort() {
        let executor = tokio::Runner::default();
        test_spawn_abort(executor, false, false);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_tokio_panic_aborts_root() {
        let executor = tokio::Runner::default();
        test_panic_aborts_root(executor);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_tokio_panic_aborts_root_caught() {
        let cfg = tokio::Config::default().with_catch_panics(true);
        let executor = tokio::Runner::new(cfg);
        test_panic_aborts_root(executor);
    }

    #[test]
    #[should_panic(expected = "blah")]
    fn test_tokio_panic_aborts_spawn() {
        let executor = tokio::Runner::default();
        test_panic_aborts_spawn(executor);
    }

    #[test]
    fn test_tokio_panic_aborts_spawn_caught() {
        let cfg = tokio::Config::default().with_catch_panics(true);
        let executor = tokio::Runner::new(cfg);
        test_panic_aborts_spawn_caught(executor);
    }

    #[test]
    #[should_panic(expected = "boom")]
    fn test_tokio_multiple_panics() {
        let executor = tokio::Runner::default();
        test_multiple_panics(executor);
    }

    #[test]
    fn test_tokio_multiple_panics_caught() {
        let cfg = tokio::Config::default().with_catch_panics(true);
        let executor = tokio::Runner::new(cfg);
        test_multiple_panics_caught(executor);
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
    fn test_tokio_spawn_dedicated() {
        let executor = tokio::Runner::default();
        test_spawn_dedicated(executor);
    }

    #[test]
    fn test_tokio_spawn() {
        let runner = tokio::Runner::default();
        test_spawn(runner);
    }

    #[test]
    fn test_tokio_spawn_abort_on_parent_abort() {
        let runner = tokio::Runner::default();
        test_spawn_abort_on_parent_abort(runner);
    }

    #[test]
    fn test_tokio_spawn_abort_on_parent_completion() {
        let runner = tokio::Runner::default();
        test_spawn_abort_on_parent_completion(runner);
    }

    #[test]
    fn test_tokio_spawn_cascading_abort() {
        let runner = tokio::Runner::default();
        test_spawn_cascading_abort(runner);
    }

    #[test]
    fn test_tokio_child_survives_sibling_completion() {
        let runner = tokio::Runner::default();
        test_child_survives_sibling_completion(runner);
    }

    #[test]
    fn test_tokio_spawn_clone_chain() {
        let runner = tokio::Runner::default();
        test_spawn_clone_chain(runner);
    }

    #[test]
    fn test_tokio_spawn_sparse_clone_chain() {
        let runner = tokio::Runner::default();
        test_spawn_sparse_clone_chain(runner);
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
            test_spawn_blocking_panic_caught(executor, dedicated);
        }
    }

    #[test]
    fn test_tokio_spawn_blocking_abort() {
        for (dedicated, blocking) in [(false, true), (true, false)] {
            let executor = tokio::Runner::default();
            test_spawn_abort(executor, dedicated, blocking);
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

    #[test_collect_traces]
    fn test_deterministic_instrument_tasks(traces: TraceStorage) {
        let executor = deterministic::Runner::new(deterministic::Config::default());
        executor.start(|context| async move {
            context
                .with_label("test")
                .instrumented()
                .spawn(|context| async move {
                    tracing::info!(field = "test field", "test log");

                    context
                        .with_label("inner")
                        .instrumented()
                        .spawn(|_| async move {
                            tracing::info!("inner log");
                        })
                        .await
                        .unwrap();
                })
                .await
                .unwrap();
        });

        let info_traces = traces.get_by_level(Level::INFO);
        assert_eq!(info_traces.len(), 2);

        // Outer log (single span)
        info_traces
            .expect_event_at_index(0, |event| {
                event.metadata.expect_content_exact("test log")?;
                event.metadata.expect_field_count(1)?;
                event.metadata.expect_field_exact("field", "test field")?;
                event.expect_span_count(1)?;
                event.expect_span_at_index(0, |span| {
                    span.expect_content_exact("task")?;
                    span.expect_field_count(1)?;
                    span.expect_field_exact("name", "test")
                })
            })
            .unwrap();

        info_traces
            .expect_event_at_index(1, |event| {
                event.metadata.expect_content_exact("inner log")?;
                event.metadata.expect_field_count(0)?;
                event.expect_span_count(1)?;
                event.expect_span_at_index(0, |span| {
                    span.expect_content_exact("task")?;
                    span.expect_field_count(1)?;
                    span.expect_field_exact("name", "test_inner")
                })
            })
            .unwrap();
    }
}
