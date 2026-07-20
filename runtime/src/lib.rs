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
//! Stability varies by primitive. See [README](https://github.com/commonwarexyz/monorepo#stability) for details.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_macros::stability_scope;

#[macro_use]
mod macros;

mod network;
mod process;
mod storage;

stability_scope!(ALPHA {
    #[cfg(feature = "arbitrary")]
    pub mod conformance;
    pub mod deterministic;
    pub mod mocks;
});
stability_scope!(ALPHA, cfg(not(target_arch = "wasm32")) {
    pub mod benchmarks;
});
stability_scope!(ALPHA, cfg(any(feature = "iouring-storage", feature = "iouring-network")) {
    mod iouring;
});
stability_scope!(BETA, cfg(not(target_arch = "wasm32")) {
    pub mod tokio;
});
stability_scope!(BETA {
    /// Re-export of `Buf` and `BufMut` traits for usage with [I/O buffers](iobuf).
    pub use bytes::{Buf, BufMut};
    use commonware_macros::select;
    use commonware_parallel::Rayon;
    /// Re-export of [governor::Quota] for rate limiting configuration.
    pub use governor::Quota;
    use iobuf::PoolError;
    use std::{
        future::Future,
        io::Error as IoError,
        net::SocketAddr,
        num::NonZeroUsize,
        sync::Arc,
        time::{Duration, SystemTime},
    };
    pub(crate) use telemetry::metrics::{METRICS_PREFIX, child_label, prefixed_name};
    use thiserror::Error;

    pub mod iobuf;
    pub use iobuf::{
        BufferPool, BufferPoolClassConfig, BufferPoolConfig, BufferPoolThreadCache,
        Builder as IoBufsBuilder, IoBuf, IoBufMut, IoBufs, IoBufsMut, cache_line_size, page_size,
    };

    pub mod utils;
    pub use utils::*;

    pub mod telemetry;

    /// Default [`Blob`] version used when no version is specified via [`Storage::open`].
    pub const DEFAULT_BLOB_VERSION: u16 = 0;

    /// Errors that can occur when interacting with the runtime.
    #[derive(Error, Debug, Clone)]
    pub enum Error {
        #[error("exited")]
        Exited,
        #[error("closed")]
        Closed,
        #[error("aborted")]
        Aborted,
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
        #[error("dns resolution failed: {0}")]
        ResolveFailed(String),
        #[error(
            "partition name invalid, must only contain alphanumeric, dash ('-'), or underscore ('_') characters: {0}"
        )]
        PartitionNameInvalid(String),
        #[error("partition creation failed: {0}")]
        PartitionCreationFailed(String),
        #[error("partition missing: {0}")]
        PartitionMissing(String),
        #[error("partition corrupt: {0}")]
        PartitionCorrupt(String),
        #[error("blob open failed: {0}/{1} error: {2}")]
        BlobOpenFailed(String, String, Arc<IoError>),
        #[error("blob missing: {0}/{1}")]
        BlobMissing(String, String),
        #[error("blob resize failed: {0}/{1} error: {2}")]
        BlobResizeFailed(String, String, Arc<IoError>),
        #[error("blob sync failed: {0}/{1} error: {2}")]
        BlobSyncFailed(String, String, Arc<IoError>),
        #[error("blob insufficient length")]
        BlobInsufficientLength,
        #[error("blob corrupt: {0}/{1} reason: {2}")]
        BlobCorrupt(String, String, String),
        #[error("blob version mismatch: expected one of {expected:?}, found {found}")]
        BlobVersionMismatch {
            expected: std::ops::RangeInclusive<u16>,
            found: u16,
        },
        #[error("invalid or missing checksum")]
        InvalidChecksum,
        #[error("offset overflow")]
        OffsetOverflow,
        #[error("io error: {0}")]
        Io(Arc<IoError>),
        #[error("buffer pool: {0}")]
        Pool(#[from] PoolError),
    }

    impl From<IoError> for Error {
        fn from(err: IoError) -> Self {
            Self::Io(Arc::new(err))
        }
    }

    /// Interface that any task scheduler must implement to start
    /// running tasks.
    pub trait Runner {
        /// Context defines the environment available to tasks.
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

    /// The full identity of a [`Supervisor`] handle.
    #[derive(Clone, Debug, Default)]
    pub struct Name {
        /// Label prefix built by successive [`Supervisor::child`] calls.
        pub label: String,
        /// Attributes attached via [`Supervisor::with_attribute`].
        pub attributes: Vec<(String, String)>,
    }

    /// Interface to track task hierarchy and identity.
    pub trait Supervisor: Send + Sync + 'static {
        /// Return the current label prefix and attributes.
        fn name(&self) -> Name;

        /// Create a named child context with a new supervision-tree node.
        ///
        /// This appends `label` to the current metric prefix and creates a
        /// child in the supervision tree. Use static role names like
        /// `"engine"`, `"worker"`, or `"resolver"`. Dynamic values belong in
        /// [`Supervisor::with_attribute`] so metric names remain bounded.
        ///
        /// Labels must start with `[a-zA-Z]` and contain only
        /// `[a-zA-Z0-9_]`. Runtime-reserved metric prefixes must not be used.
        #[must_use]
        fn child(&self, label: &'static str) -> Self;

        /// Add a key-value attribute to this context's identity.
        ///
        /// Attributes are attached to metrics registered in this context and
        /// any child contexts. Unlike [`Supervisor::child`], attributes do not
        /// affect metric names and do not create a supervision-tree edge. This
        /// makes them the right place for dynamic values like epochs, rounds,
        /// shards, or peer identifiers.
        ///
        /// Keys must start with `[a-zA-Z]` and contain only `[a-zA-Z0-9_]`.
        /// Values can be any string. If the key already exists, its value is
        /// replaced.
        ///
        /// ```text
        /// context
        ///   |-- child("orchestrator")
        ///         |-- with_attribute("epoch", "5")
        ///               |-- counter: votes      -> orchestrator_votes{epoch="5"}
        ///               |-- counter: proposals  -> orchestrator_proposals{epoch="5"}
        ///               |-- child("engine")
        ///                     |-- gauge: height -> orchestrator_engine_height{epoch="5"}
        /// ```
        ///
        /// This pattern avoids wrapping every metric in a `Family` and avoids
        /// putting dynamic values in metric names like
        /// `orchestrator_epoch_5_votes`.
        ///
        /// Attributes do not reduce cardinality. N epochs still means N time
        /// series. They just make metrics easier to query, filter, and
        /// aggregate.
        ///
        /// # Family Label Conflicts
        ///
        /// When using `Family` metrics, avoid attribute keys that match the
        /// family's label field names. A conflict produces duplicate labels in
        /// the encoded output, which is invalid Prometheus format.
        ///
        /// ```ignore
        /// #[derive(EncodeLabelSet)]
        /// struct Labels { env: String }
        ///
        /// // Bad: attribute "env" conflicts with Family field "env".
        /// let ctx = context.child("api").with_attribute("env", "prod");
        /// let family: Family<Labels, Counter> = Family::default();
        /// ctx.register("requests", "help", family);
        ///
        /// // Good: use distinct names.
        /// let ctx = context.child("api").with_attribute("region", "us_east");
        /// ```
        ///
        /// # Querying The Latest Attribute
        ///
        /// To query the latest attribute value dynamically, create a gauge to
        /// track the current value:
        ///
        /// ```ignore
        /// let latest_epoch = context
        ///     .child("orchestrator")
        ///     .register("latest_epoch", "current epoch", Gauge::default());
        /// latest_epoch.set(current_epoch);
        /// ```
        ///
        /// A dashboard can then query `max(orchestrator_latest_epoch)` and use
        /// the result as a variable in queries such as
        /// `consensus_engine_votes_total{epoch="$latest_epoch"}`.
        #[must_use]
        fn with_attribute(self, key: &'static str, value: impl std::fmt::Display) -> Self;
    }

    /// Interface that any task scheduler must implement to spawn tasks.
    pub trait Spawner: Supervisor {
        /// Return a [`Spawner`] that schedules the next task onto the runtime's shared executor.
        ///
        /// Set `blocking` to `true` when the task may hold the thread for a short, blocking operation.
        /// Runtimes can use this hint to move the work to a blocking-friendly pool so asynchronous
        /// tasks on a work-stealing executor are not starved. For long-lived, blocking work, use
        /// [`Spawner::dedicated`] instead.
        ///
        /// The shared executor with `blocking == false` is the default spawn mode.
        #[must_use]
        fn shared(self, blocking: bool) -> Self;

        /// Return a [`Spawner`] that runs the next task on a dedicated thread when the runtime supports it.
        ///
        /// Reserve this for long-lived or prioritized tasks that should not compete for resources in the
        /// shared executor.
        ///
        /// This is not the default behavior. See [`Spawner::shared`] for more information.
        #[must_use]
        fn dedicated(self) -> Self;

        /// Spawn a task with the current context.
        ///
        /// Unlike directly awaiting a future, the task starts running immediately even if the caller
        /// never awaits the returned [`Handle`].
        ///
        /// # Mandatory Supervision
        ///
        /// All tasks are supervised. When a parent task finishes or is aborted, all its descendants are aborted.
        ///
        /// Spawn consumes the current context and runs the task at a new child node. Additional supervised
        /// children are created explicitly with [`Supervisor::child`].
        ///
        /// ```txt
        /// ctx_a
        ///   |
        ///   +-- child("worker") ---> ctx_c
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
        /// [`Spawner::dedicated`] and [`Spawner::shared`] only affect the
        /// handle they return. [`Supervisor::child`] and [`Spawner::spawn`]
        /// both start child task contexts from a clean spawn configuration.
        ///
        /// Child tasks should assume they start from a clean configuration without needing to inspect how their
        /// parent was configured.
        fn spawn<F, Fut, T>(self, f: F) -> Handle<T>
        where
            Self: Sized,
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

    /// Interface that runtimes implement to provide parallel execution strategies.
    pub trait Strategizer: Spawner {
        /// Returns a new [Rayon] strategy with the requested parallelism.
        ///
        /// # Arguments
        /// - `parallelism`: The number of tasks to execute concurrently in the pool.
        ///
        /// # Panics
        ///
        /// Panics if the runtime cannot initialize the strategy's backing Rayon thread pool.
        fn strategy(&self, parallelism: NonZeroUsize) -> Rayon;
    }

    /// Interface to register and encode metrics.
    pub trait Metrics: Supervisor {
        /// Register a metric with the runtime.
        ///
        /// Any registered metric includes the current context label as its name
        /// prefix and the current context attributes as Prometheus labels. See
        /// [`Supervisor`] for the identity model and examples.
        ///
        /// The returned [`telemetry::metrics::Registered`] value must be retained for as long as the
        /// metric should remain exposed. Dropping the returned handle unregisters
        /// the metric immediately.
        ///
        /// Re-registering the same metric key (same prefixed name and attributes)
        /// returns another handle to the existing metric when the concrete metric
        /// type matches. Registering the same key with a different metric type
        /// panics.
        ///
        /// Names must start with `[a-zA-Z]` and contain only `[a-zA-Z0-9_]`.
        fn register<N: Into<String>, H: Into<String>, M: telemetry::metrics::Metric>(
            &self,
            name: N,
            help: H,
            metric: M,
        ) -> telemetry::metrics::Registered<M>;

        /// Encode all metrics into a buffer.
        fn encode(&self) -> String;
    }

    /// A direct (non-keyed) rate limiter using the provided [governor::clock::Clock] `C`.
    ///
    /// This is a convenience type alias for creating single-entity rate limiters.
    /// For per-key rate limiting, use [KeyedRateLimiter].
    pub type RateLimiter<C> = governor::RateLimiter<
        governor::state::NotKeyed,
        governor::state::InMemoryState,
        C,
        governor::middleware::NoOpMiddleware<<C as governor::clock::Clock>::Instant>,
    >;

    /// A rate limiter keyed by `K` using the provided [governor::clock::Clock] `C`.
    ///
    /// This is a convenience type alias for creating per-peer rate limiters
    /// using governor's [HashMapStateStore].
    ///
    /// [HashMapStateStore]: governor::state::keyed::HashMapStateStore
    pub type KeyedRateLimiter<K, C> = governor::RateLimiter<
        K,
        governor::state::keyed::HashMapStateStore<K>,
        C,
        governor::middleware::NoOpMiddleware<<C as governor::clock::Clock>::Instant>,
    >;

    /// Interface that any task scheduler must implement to provide
    /// time-based operations.
    ///
    /// It is necessary to mock time to provide deterministic execution
    /// of arbitrary tasks.
    pub trait Clock:
        governor::clock::Clock<Instant = SystemTime>
        + governor::clock::ReasonablyRealtime
        + Send
        + Sync
        + 'static
    {
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
                    result = future => Ok(result),
                    _ = self.sleep(duration) => Err(Error::Timeout),
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
    pub trait Network: Send + Sync + 'static {
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

    /// Interface for DNS resolution.
    pub trait Resolver: Send + Sync + 'static {
        /// Resolve a hostname to IP addresses.
        ///
        /// Returns a list of IP addresses that the hostname resolves to.
        fn resolve(
            &self,
            host: &str,
        ) -> impl Future<Output = Result<Vec<std::net::IpAddr>, Error>> + Send;
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
        ///
        /// # Warning
        ///
        /// If the sink returns an error, part of the message may still be delivered.
        /// After any error, the sink is no longer reusable and subsequent sends will
        /// return [`Error::Closed`].
        ///
        /// Dropping the future (e.g. via `select!`) also poisons the sink, since a
        /// partial write may have occurred.
        fn send(
            &mut self,
            bufs: impl Into<IoBufs> + Send,
        ) -> impl Future<Output = Result<(), Error>> + Send;
    }

    /// Interface that any runtime must implement to receive
    /// messages over a network connection.
    pub trait Stream: Sync + Send + 'static {
        /// Receive exactly `len` bytes from the stream.
        ///
        /// The runtime allocates the buffer and returns it as `IoBufs`.
        ///
        /// # Warning
        ///
        /// If the stream returns an error, partially read data may be discarded.
        /// After any error, the stream is no longer reusable and subsequent receives
        /// will return [`Error::Closed`].
        ///
        /// Dropping the future (e.g. via `select!`) also poisons the stream, since
        /// partially read data may be lost.
        fn recv(&mut self, len: usize) -> impl Future<Output = Result<IoBufs, Error>> + Send;

        /// Peek at buffered data without consuming.
        ///
        /// Returns up to `max_len` bytes from the internal buffer, or an empty slice
        /// if no data is currently buffered. This does not perform any I/O or block.
        ///
        /// This is useful e.g. for parsing length prefixes without committing to a read
        /// or paying the cost of async.
        fn peek(&self, max_len: usize) -> &[u8];
    }

    /// Interface to interact with storage.
    ///
    /// To support storage implementations that enable concurrent reads and
    /// writes, blobs are responsible for maintaining synchronization.
    ///
    /// Storage can be backed by a local filesystem, cloud storage, etc.
    ///
    /// # Durability
    ///
    /// Runtimes must ensure that any data readable when user code starts
    /// executing is crash-durable. Storage structures may rely on this during
    /// recovery: data read at initialization can be assumed to survive a
    /// subsequent crash without an explicit [`Blob::sync`].
    ///
    /// # Partition Names
    ///
    /// Partition names must be non-empty and contain only ASCII alphanumeric
    /// characters, dashes (`-`), or underscores (`_`). Names containing other
    /// characters (e.g., `/`, `.`, spaces) will return an error.
    pub trait Storage: Send + Sync + 'static {
        /// The readable/writeable storage buffer that can be opened by this Storage.
        type Blob: Blob;

        /// [`Storage::open_versioned`] with [`DEFAULT_BLOB_VERSION`] as the only value
        /// in the versions range. The blob version is omitted from the return value.
        fn open(
            &self,
            partition: &str,
            name: &[u8],
        ) -> impl Future<Output = Result<(Self::Blob, u64), Error>> + Send {
            async move {
                let (blob, size, _) = self
                    .open_versioned(partition, name, DEFAULT_BLOB_VERSION..=DEFAULT_BLOB_VERSION)
                    .await?;
                Ok((blob, size))
            }
        }

        /// Open an existing blob in a given partition or create a new one, returning
        /// the blob and its length.
        ///
        /// Multiple instances of the same blob can be opened concurrently, however,
        /// writing to the same blob concurrently may lead to undefined behavior.
        ///
        /// An Ok result indicates the blob is durably created (or already exists).
        ///
        /// # Versions
        ///
        /// Blobs are versioned. If the blob's version is not in `versions`, returns
        /// [Error::BlobVersionMismatch].
        ///
        /// # Returns
        ///
        /// A tuple of (blob, logical_size, blob_version).
        fn open_versioned(
            &self,
            partition: &str,
            name: &[u8],
            versions: std::ops::RangeInclusive<u16>,
        ) -> impl Future<Output = Result<(Self::Blob, u64, u16), Error>> + Send;

        /// Remove a blob from a given partition.
        ///
        /// If no `name` is provided, the entire partition is removed.
        ///
        /// An Ok result indicates the blob is durably removed.
        ///
        /// # Read-after-remove
        ///
        /// Removal unlinks the blob's name but does not invalidate previously opened handles:
        /// they remain fully readable until dropped, whether the blob was removed by name or by
        /// removing its entire partition. This includes bytes written but never synced. Physical
        /// resources are reclaimed once the last handle is dropped.
        ///
        /// Re-opening a removed blob's name creates a new, independent blob; handles opened
        /// before the removal continue to observe the removed blob's contents.
        ///
        /// Mutating a removed blob (e.g. via [`Blob::write_at`], [`Blob::resize`], or
        /// [`Blob::sync`]) is unspecified: implementations may succeed or return an error.
        fn remove(
            &self,
            partition: &str,
            name: Option<&[u8]>,
        ) -> impl Future<Output = Result<(), Error>> + Send;

        /// Return all blobs in a given partition.
        fn scan(&self, partition: &str)
        -> impl Future<Output = Result<Vec<Vec<u8>>, Error>> + Send;
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
        /// Read `len` bytes at `offset` into caller-provided buffer(s).
        ///
        /// The caller provides the buffer(s), and the implementation fills it with
        /// exactly `len` bytes of data read from the blob starting at `offset`.
        /// Returns the same buffer(s), filled with data.
        ///
        /// # Contract
        ///
        /// - The returned buffers reuse caller-provided storage, with exactly `len`
        ///   bytes filled from `offset`.
        /// - Caller-provided chunk layout is preserved.
        ///
        /// # Panics
        ///
        /// Panics if `len` exceeds the total capacity of `bufs`.
        fn read_at_buf(
            &self,
            offset: u64,
            len: usize,
            bufs: impl Into<IoBufsMut> + Send,
        ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send;

        /// Read `len` bytes at `offset`, returning a buffer(s) with exactly `len` bytes
        /// of data read from the blob starting at `offset`.
        ///
        /// To reuse a buffer(s), use [`Blob::read_at_buf`].
        fn read_at(
            &self,
            offset: u64,
            len: usize,
        ) -> impl Future<Output = Result<IoBufsMut, Error>> + Send;

        /// Write `bufs` to the blob at the given offset.
        fn write_at(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> impl Future<Output = Result<(), Error>> + Send;

        /// Write `bufs` to the blob at the given offset and durably persist that write.
        ///
        /// This is not a durability barrier for previous operations. When it completes,
        /// only the bytes submitted to this call are guaranteed durable. Earlier unsynced
        /// [`Blob::write_at`] or [`Blob::resize`] calls require [`Blob::sync`] to become
        /// durable.
        fn write_at_sync(
            &self,
            offset: u64,
            bufs: impl Into<IoBufs> + Send,
        ) -> impl Future<Output = Result<(), Error>> + Send;

        /// Resize the blob to the given length.
        ///
        /// If the length is greater than the current length, the blob is extended with zeros.
        /// If the length is less than the current length, the blob is resized.
        fn resize(&self, len: u64) -> impl Future<Output = Result<(), Error>> + Send;

        /// Ensure all pending data is durably persisted.
        fn sync(&self) -> impl Future<Output = Result<(), Error>> + Send;

        /// Request that all pending data is durably persisted.
        ///
        /// Awaiting this future waits until the sync has started. Awaiting the returned
        /// [`Handle`] waits for the same durability guarantee as [`Blob::sync`].
        fn start_sync(&self) -> impl Future<Output = Handle<()>> + Send;
    }

    /// Interface that any runtime must implement to provide buffer pools.
    pub trait BufferPooler: Send + Sync + 'static {
        /// Returns the network [BufferPool].
        fn network_buffer_pool(&self) -> &BufferPool;

        /// Returns the storage [BufferPool].
        fn storage_buffer_pool(&self) -> &BufferPool;
    }
});
stability_scope!(BETA, cfg(feature = "external") {
    /// Interface that runtimes can implement to constrain the execution latency of a future.
    pub trait Pacer: Clock + Send + Sync + 'static {
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
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::telemetry::metrics::{
        EncodeLabelKey, EncodeLabelSetTrait as EncodeLabelSet,
        EncodeLabelValueTrait as EncodeLabelValue, LabelSetEncoder, count_running_tasks,
        raw::{Counter, Family},
    };
    use commonware_macros::select;
    use commonware_parallel::Strategy as _;
    use commonware_utils::{
        NZU32, NZUsize, SystemTimeExt,
        channel::{mpsc, oneshot},
        futures::Pool as FuturesPool,
        sync::Mutex,
    };
    use futures::{
        FutureExt,
        future::{pending, ready},
        join, pin_mut,
    };
    use rstest::rstest;
    use std::{
        pin::Pin,
        sync::{
            Arc,
            atomic::{AtomicU32, Ordering},
        },
        task::{Context as TContext, Poll, Waker},
    };
    use utils::reschedule;

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_error_future<R: Runner>(#[case] runner: R) {
        #[allow(clippy::unused_async)]
        async fn error_future() -> Result<&'static str, &'static str> {
            Err("An error occurred")
        }
        let result = runner.start(|_| error_future());
        assert_eq!(result, Err("An error occurred"));
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_handle_can_use_futures_pool<R: Runner>(#[case] runner: R) {
        runner.start(|_| async move {
            let mut pool = FuturesPool::<Result<(), Error>>::default();
            pool.push(Handle::ready(Ok(())));
            assert!(pool.next_completed().await.is_ok());
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_clock_sleep<R: Runner>(#[case] runner: R)
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_clock_sleep_until<R: Runner>(#[case] runner: R)
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_clock_sleep_until_far_future<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let sleep = context.sleep_until(SystemTime::limit());
            let result = context.timeout(Duration::from_millis(1), sleep).await;
            assert!(matches!(result, Err(Error::Timeout)));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_clock_timeout<R: Runner>(#[case] runner: R)
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_root_finishes<R: Runner>(#[case] runner: R)
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_after_abort<R>(#[case] runner: R)
    where
        R: Runner,
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            // Create a child context
            let child = context.child("child");

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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_abort<R: Runner>(
        #[case] runner: R,
        #[values(
            Execution::Shared(false),
            Execution::Shared(true),
            Execution::Dedicated
        )]
        execution: Execution,
    ) where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let context = match execution {
                Execution::Dedicated => context.dedicated(),
                Execution::Shared(blocking) => context.shared(blocking),
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::deterministic_caught(deterministic::Runner::new(
        deterministic::Config::default().with_catch_panics(true)
    ))]
    #[case::tokio(tokio::Runner::default())]
    #[case::tokio_caught(tokio::Runner::new(tokio::Config::default().with_catch_panics(true)))]
    #[should_panic(expected = "blah")]
    fn test_panic_aborts_root<R: Runner>(#[case] runner: R) {
        let result: Result<(), Error> = runner.start(|_| async move {
            panic!("blah");
        });
        result.unwrap_err();
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    #[should_panic(expected = "blah")]
    fn test_panic_aborts_spawn<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            context.child("panic").spawn(|_| async move {
                panic!("blah");
            });

            // Loop until panic
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::new(
        deterministic::Config::default().with_catch_panics(true)
    ))]
    #[case::tokio(tokio::Runner::new(tokio::Config::default().with_catch_panics(true)))]
    fn test_panic_aborts_spawn_caught<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        let result: Result<(), Error> = runner.start(|context| async move {
            let result = context.child("panic").spawn(|_| async move {
                panic!("blah");
            });
            result.await
        });
        assert!(matches!(result, Err(Error::Exited)));
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    #[should_panic(expected = "boom")]
    fn test_multiple_panics<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            context.child("panic").spawn(|_| async move {
                panic!("boom 1");
            });
            context.child("panic").spawn(|_| async move {
                panic!("boom 2");
            });
            context.child("panic").spawn(|_| async move {
                panic!("boom 3");
            });

            // Loop until panic
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::new(
        deterministic::Config::default().with_catch_panics(true)
    ))]
    #[case::tokio(tokio::Runner::new(tokio::Config::default().with_catch_panics(true)))]
    fn test_multiple_panics_caught<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        let (res1, res2, res3) = runner.start(|context| async move {
            let handle1 = context.child("panic").spawn(|_| async move {
                panic!("boom 1");
            });
            let handle2 = context.child("panic").spawn(|_| async move {
                panic!("boom 2");
            });
            let handle3 = context.child("panic").spawn(|_| async move {
                panic!("boom 3");
            });

            join!(handle1, handle2, handle3)
        });
        assert!(matches!(res1, Err(Error::Exited)));
        assert!(matches!(res2, Err(Error::Exited)));
        assert!(matches!(res3, Err(Error::Exited)));
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_select<R: Runner>(#[case] runner: R) {
        runner.start(|_| async move {
            // Test first branch
            let output = Mutex::new(0);
            select! {
                v1 = ready(1) => {
                    *output.lock() = v1;
                },
                v2 = ready(2) => {
                    *output.lock() = v2;
                },
            };
            assert_eq!(*output.lock(), 1);

            // Test second branch
            select! {
                v1 = std::future::pending::<i32>() => {
                    *output.lock() = v1;
                },
                v2 = ready(2) => {
                    *output.lock() = v2;
                },
            };
            assert_eq!(*output.lock(), 2);
        });
    }

    /// Ensure future fusing works as expected.
    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_select_loop<R: Runner>(#[case] runner: R)
    where
        R::Context: Clock,
    {
        runner.start(|context| async move {
            // Should hit timeout
            let (sender, mut receiver) = mpsc::unbounded_channel();
            for _ in 0..2 {
                select! {
                    v = receiver.recv() => {
                        panic!("unexpected value: {v:?}");
                    },
                    _ = context.sleep(Duration::from_millis(100)) => {
                        continue;
                    },
                };
            }

            // Populate channel
            sender.send(0).unwrap();
            sender.send(1).unwrap();

            // Prefer not reading channel without losing messages
            select! {
                _ = async {} => {
                    // Skip reading from channel even though populated
                },
                v = receiver.recv() => {
                    panic!("unexpected value: {v:?}");
                },
            };

            // Process messages
            for i in 0..2 {
                select! {
                    _ = context.sleep(Duration::from_millis(100)) => {
                        panic!("timeout");
                    },
                    v = receiver.recv() => {
                        assert_eq!(v.unwrap(), i);
                    },
                };
            }
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_storage_operations<R: Runner>(#[case] runner: R)
    where
        R::Context: Storage,
    {
        runner.start(|context| async move {
            let partition = "test_partition";
            let name = b"test_blob";

            // Open a new blob
            let (blob, size) = context
                .open(partition, name)
                .await
                .expect("Failed to open blob");
            assert_eq!(size, 0, "new blob should have size 0");

            // Write data to the blob
            let data = b"Hello, Storage!";
            blob.write_at(0, data)
                .await
                .expect("Failed to write to blob");

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

            // Read data from the blob
            let read = blob
                .read_at(0, data.len())
                .await
                .expect("Failed to read from blob");
            assert_eq!(read.coalesce(), data);

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
            let read = blob.read_at(7, 7).await.expect("Failed to read data");
            assert_eq!(read.coalesce(), b"Storage");

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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_blob_read_write<R: Runner>(#[case] runner: R)
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
            blob.write_at(0, data1)
                .await
                .expect("Failed to write data1");
            blob.write_at(5, data2)
                .await
                .expect("Failed to write data2");

            // Read data back
            let read = blob.read_at(0, 10).await.expect("Failed to read data");
            let read = read.coalesce();
            assert_eq!(&read.as_ref()[..5], data1);
            assert_eq!(&read.as_ref()[5..], data2);

            // Read past end of blob
            let result = blob.read_at(10, 10).await;
            assert!(result.is_err());

            // Rewrite data without affecting length
            let data3 = b"Store";
            blob.write_at(5, data3)
                .await
                .expect("Failed to write data3");

            // Read data back
            let read = blob.read_at(0, 10).await.expect("Failed to read data");
            let read = read.coalesce();
            assert_eq!(&read.as_ref()[..5], data1);
            assert_eq!(&read.as_ref()[5..], data3);

            // Read past end of blob
            let result = blob.read_at(10, 10).await;
            assert!(result.is_err());
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_blob_resize<R: Runner>(#[case] runner: R)
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
            blob.write_at(0, data.to_vec())
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
            let read_buf = blob.read_at(0, data.len()).await.unwrap();
            assert_eq!(read_buf.coalesce(), data);

            // Read extended part (should be zeros)
            let extended_part = blob.read_at(data.len() as u64, data.len()).await.unwrap();
            assert_eq!(extended_part.coalesce(), vec![0; data.len()].as_slice());

            // Truncate the blob
            blob.resize(data.len() as u64).await.unwrap();
            blob.sync().await.unwrap();

            // Reopen to check truncation
            let (blob, size) = context.open(partition, name).await.unwrap();
            assert_eq!(size, data.len() as u64);

            // Read truncated data
            let read_buf = blob.read_at(0, data.len()).await.unwrap();
            assert_eq!(read_buf.coalesce(), data);
            blob.sync().await.unwrap();
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_many_partition_read_write<R: Runner>(#[case] runner: R)
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
                blob.write_at(0, data1)
                    .await
                    .expect("Failed to write data1");
                blob.write_at(5 + additional as u64, data2)
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
                    .read_at(0, 10 + additional)
                    .await
                    .expect("Failed to read data");
                let read = read.coalesce();
                assert_eq!(&read.as_ref()[..5], b"Hello");
                assert_eq!(&read.as_ref()[5 + additional..], b"World");
            }
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_blob_read_past_length<R: Runner>(#[case] runner: R)
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
            let result = blob.read_at(0, 10).await;
            assert!(result.is_err());

            // Write data to the blob
            let data = b"Hello, Storage!".to_vec();
            blob.write_at(0, data)
                .await
                .expect("Failed to write to blob");

            // Read data past file length (non-empty file)
            let result = blob.read_at(0, 20).await;
            assert!(result.is_err());
        })
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_blob_clone_and_concurrent_read<R: Runner>(#[case] runner: R)
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
            blob.write_at(0, data)
                .await
                .expect("Failed to write to blob");

            // Sync the blob
            blob.sync().await.expect("Failed to sync blob");

            // Read data from the blob in clone
            let check1 = context.child("check1").spawn({
                let blob = blob.clone();
                let data_len = data.len();
                move |_| async move {
                    let read = blob
                        .read_at(0, data_len)
                        .await
                        .expect("Failed to read from blob");
                    assert_eq!(read.coalesce(), data);
                }
            });
            let check2 = context.child("check2").spawn({
                let blob = blob.clone();
                let data_len = data.len();
                move |_| async move {
                    let read = blob
                        .read_at(0, data_len)
                        .await
                        .expect("Failed to read from blob");
                    assert_eq!(read.coalesce(), data);
                }
            });

            // Wait for both reads to complete
            let result = join!(check1, check2);
            assert!(result.0.is_ok());
            assert!(result.1.is_ok());

            // Read data from the blob
            let read = blob
                .read_at(0, data.len())
                .await
                .expect("Failed to read from blob");
            assert_eq!(read.coalesce(), data);

            // Drop the blob
            drop(blob);

            // Ensure no blobs still open
            let buffer = context.encode();
            assert!(buffer.contains("open_blobs 0"));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_shutdown<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill = 9;
        runner.start(|context| async move {
            // Spawn a task that waits for signal
            let before = context.child("before").spawn(move |context| async move {
                let mut signal = context.stopped();
                let value = (&mut signal).await.unwrap();
                assert_eq!(value, kill);
                drop(signal);
            });

            // Signal the tasks and wait for them to stop
            let result = context.child("stop").stop(kill, None).await;
            assert!(result.is_ok());

            // Spawn a task after stop is called
            let after = context.child("after").spawn(move |context| async move {
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_shutdown_multiple_signals<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill = 42;
        runner.start(|context| async move {
            let (started_tx, mut started_rx) = mpsc::channel(3);
            let counter = Arc::new(AtomicU32::new(0));

            // Spawn 3 tasks that do cleanup work after receiving stop signal
            // and increment a shared counter
            let task = |context: R::Context, cleanup_duration: Duration| {
                let counter = counter.clone();
                let started_tx = started_tx.clone();
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

            let task1 = task(context.child("cleanup"), Duration::from_millis(10));
            let task2 = task(context.child("cleanup"), Duration::from_millis(20));
            let task3 = task(context.child("cleanup"), Duration::from_millis(30));

            // Give tasks time to start
            for _ in 0..3 {
                started_rx.recv().await.unwrap();
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_shutdown_timeout<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill = 42;
        runner.start(|context| async move {
            // Setup startup coordinator
            let (started_tx, started_rx) = oneshot::channel();

            // Spawn a task that never completes its cleanup
            context.child("signal").spawn(move |context| async move {
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_shutdown_multiple_stop_calls<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        let kill1 = 42;
        let kill2 = 43;

        runner.start(|context| async move {
            let (started_tx, started_rx) = oneshot::channel();
            let counter = Arc::new(AtomicU32::new(0));

            // Spawn a task that delays completion to test timing
            let task = context.child("blocking_task").spawn({
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
            let stop_task1 = context.child("stop").stop(kill1, None);
            pin_mut!(stop_task1);
            let stop_task2 = context.child("stop").stop(kill2, None);
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_unfulfilled_shutdown<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Metrics,
    {
        runner.start(|context| async move {
            // Spawn a task that waits for signal
            context.child("before").spawn(move |context| async move {
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_dedicated<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let handle = context.dedicated().spawn(|_| async move { 42 });
            assert!(matches!(handle.await, Ok(42)));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn<R: Runner>(#[case] runner: R)
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
                *child_handle2.lock() = Some(handle);

                parent_initialized_tx.send(()).unwrap();

                // Parent task completes
                parent_complete_rx.await.unwrap();
            });

            // Wait for parent task to spawn the children
            parent_initialized_rx.await.unwrap();

            // Child task completes successfully
            let child_handle = child_handle.lock().take().unwrap();
            assert!(child_handle.await.is_ok());

            // Complete the parent task
            parent_complete_tx.send(()).unwrap();

            // Wait for parent task to complete successfully
            assert!(parent_handle.await.is_ok());
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_abort_on_parent_abort<R: Runner>(#[case] runner: R)
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
                *child_handle2.lock() = Some(handle);

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
            let child_handle = child_handle.lock().take().unwrap();
            assert!(matches!(child_handle.await, Err(Error::Closed)));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_abort_on_parent_completion<R: Runner>(#[case] runner: R)
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
                *child_handle2.lock() = Some(handle);

                // Parent task completes
                parent_complete_rx.await.unwrap();
            });

            // Fire parent completion
            parent_complete_tx.send(()).unwrap();

            // Wait for parent task to complete
            assert!(parent_handle.await.is_ok());

            // Child task should resolve with error since its parent has completed
            let child_handle = child_handle.lock().take().unwrap();
            assert!(matches!(child_handle.await, Err(Error::Closed)));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_cascading_abort<R: Runner>(#[case] runner: R)
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
            let c0 = context.child("c0");
            let g0 = c0.child("g0");
            let g1 = c0.child("g1");
            let c1 = context.child("c1");
            let g2 = c1.child("g2");
            let g3 = c1.child("g3");
            let c2 = context.child("c2");
            let g4 = c2.child("g4");
            let g5 = c2.child("g5");

            // Spawn tasks
            let handles = Arc::new(Mutex::new(Vec::new()));
            let (initialized_tx, mut initialized_rx) = mpsc::channel(9);
            let root_task = context.spawn({
                let handles = handles.clone();
                move |_| async move {
                    for (context, grandchildren) in [(c0, [g0, g1]), (c1, [g2, g3]), (c2, [g4, g5])]
                    {
                        let handle = context.spawn({
                            let handles = handles.clone();
                            let initialized_tx = initialized_tx.clone();
                            move |_| async move {
                                for grandchild in grandchildren {
                                    let handle = grandchild.spawn(|_| async {
                                        pending::<()>().await;
                                    });
                                    handles.lock().push(handle);
                                    initialized_tx.send(()).await.unwrap();
                                }

                                pending::<()>().await;
                            }
                        });
                        handles.lock().push(handle);
                        initialized_tx.send(()).await.unwrap();
                    }

                    pending::<()>().await;
                }
            });

            // Wait for tasks to initialize
            for _ in 0..9 {
                initialized_rx.recv().await.unwrap();
            }

            // Verify we have all 9 handles (3 children + 6 grandchildren)
            assert_eq!(handles.lock().len(), 9);

            // Abort root task
            root_task.abort();
            assert!(matches!(root_task.await, Err(Error::Closed)));

            // All handles should resolve with error due to cascading abort
            let handles = handles.lock().drain(..).collect::<Vec<_>>();
            for handle in handles {
                assert!(matches!(handle.await, Err(Error::Closed)));
            }
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_child_survives_sibling_completion<R: Runner>(#[case] runner: R)
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
                let child_handle = context.child("child").spawn(|_| async move {
                    child_started_tx.send(()).unwrap();
                    // Wait for signal to complete
                    child_complete_rx.await.unwrap();
                });
                assert!(
                    child_handle_tx.send(child_handle).is_ok(),
                    "child handle receiver dropped"
                );

                // Spawn an independent sibling task
                let sibling_handle = context.child("sibling").spawn(move |_| async move {
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_clone_chain<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (parent_started_tx, parent_started_rx) = oneshot::channel();
            let (child_started_tx, child_started_rx) = oneshot::channel();
            let (grandchild_started_tx, grandchild_started_rx) = oneshot::channel();
            let (child_handle_tx, child_handle_rx) = oneshot::channel();
            let (grandchild_handle_tx, grandchild_handle_rx) = oneshot::channel();

            let parent = context.child("parent").spawn({
                move |context| async move {
                    let child = context.child("child").spawn({
                        move |context| async move {
                            let grandchild = context.child("grandchild").spawn({
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_sparse_clone_chain<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let (leaf_started_tx, leaf_started_rx) = oneshot::channel();
            let (leaf_handle_tx, leaf_handle_rx) = oneshot::channel();

            let parent = context.child("parent").spawn({
                move |context| async move {
                    let clone1 = context.child("clone1");
                    let clone2 = clone1.child("clone2");
                    let clone3 = clone2.child("clone3");

                    let leaf = clone3.spawn({
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_spawn_blocking<R: Runner>(
        #[case] runner: R,
        #[values(Execution::Shared(true), Execution::Dedicated)] execution: Execution,
    ) where
        R::Context: Spawner,
    {
        runner.start(|context| async move {
            let context = match execution {
                Execution::Dedicated => context.dedicated(),
                Execution::Shared(blocking) => context.shared(blocking),
            };

            let handle = context.spawn(|_| async move { 42 });
            let result = handle.await;
            assert!(matches!(result, Ok(42)));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    #[should_panic(expected = "blocking task panicked")]
    fn test_spawn_blocking_panic<R: Runner>(
        #[case] runner: R,
        #[values(Execution::Shared(true), Execution::Dedicated)] execution: Execution,
    ) where
        R::Context: Spawner + Clock,
    {
        runner.start(|context| async move {
            let spawner = match execution {
                Execution::Dedicated => context.child("blocking").dedicated(),
                Execution::Shared(blocking) => context.child("blocking").shared(blocking),
            };
            spawner.spawn(|_| async move {
                panic!("blocking task panicked");
            });

            // Loop until panic
            loop {
                context.sleep(Duration::from_millis(100)).await;
            }
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::new(
        deterministic::Config::default().with_catch_panics(true)
    ))]
    #[case::tokio(tokio::Runner::new(tokio::Config::default().with_catch_panics(true)))]
    fn test_spawn_blocking_panic_caught<R: Runner>(
        #[case] runner: R,
        #[values(Execution::Shared(true), Execution::Dedicated)] execution: Execution,
    ) where
        R::Context: Spawner + Clock,
    {
        let result: Result<(), Error> = runner.start(|context| async move {
            let spawner = match execution {
                Execution::Dedicated => context.child("blocking").dedicated(),
                Execution::Shared(blocking) => context.child("blocking").shared(blocking),
            };
            let handle = spawner.spawn(|_| async move {
                panic!("blocking task panicked");
            });
            handle.await
        });
        assert!(matches!(result, Err(Error::Exited)));
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_circular_reference_prevents_cleanup<R: Runner>(#[case] runner: R) {
        runner.start(|_| async move {
            // Setup tracked resource
            let dropper = Arc::new(());
            let executor = deterministic::Runner::default();
            executor.start({
                let dropper = dropper.clone();
                move |context| async move {
                    // Create tasks with circular dependencies through channels
                    let (setup_tx, mut setup_rx) = mpsc::unbounded_channel::<()>();
                    let (tx1, mut rx1) = mpsc::unbounded_channel::<()>();
                    let (tx2, mut rx2) = mpsc::unbounded_channel::<()>();

                    // Task 1 holds tx2 and waits on rx1
                    context.child("task1").spawn({
                        let setup_tx = setup_tx.clone();
                        let dropper = dropper.clone();
                        move |_| async move {
                            // Setup deadlock and mark ready
                            tx2.send(()).unwrap();
                            rx1.recv().await.unwrap();
                            setup_tx.send(()).unwrap();

                            // Wait forever
                            while rx1.recv().await.is_some() {}
                            drop(tx2);
                            drop(dropper);
                        }
                    });

                    // Task 2 holds tx1 and waits on rx2
                    context.child("task2").spawn(move |_| async move {
                        // Setup deadlock and mark ready
                        tx1.send(()).unwrap();
                        rx2.recv().await.unwrap();
                        setup_tx.send(()).unwrap();

                        // Wait forever
                        while rx2.recv().await.is_some() {}
                        drop(tx1);
                        drop(dropper);
                    });

                    // Wait for tasks to start
                    setup_rx.recv().await.unwrap();
                    setup_rx.recv().await.unwrap();
                }
            });

            // After runtime drop, both tasks should be cleaned up
            Arc::try_unwrap(dropper).expect("references remaining");
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_late_waker<R: Runner>(#[case] runner: R)
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
            context.child("capture_waker").spawn(move |_| async move {
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

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Assert label
            assert_eq!(context.name().label, "");

            // Register a metric
            let counter = Counter::<u64>::default();
            let _registered = context.register("test", "test", counter.clone());

            // Increment the counter
            counter.inc();

            // Encode metrics
            let buffer = context.encode();
            assert!(buffer.contains("test_total 1"));

            // Nested context
            let context = context.child("nested");
            let nested_counter = Counter::<u64>::default();
            let _nested_registered = context.register("test", "test", nested_counter.clone());

            // Increment the counter
            nested_counter.inc();

            // Encode metrics
            let buffer = context.encode();
            assert!(buffer.contains("nested_test_total 1"));
            assert!(buffer.contains("test_total 1"));
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_with_attribute<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Create context with a attribute
            let ctx_epoch5 = context.child("consensus").with_attribute("epoch", "e5");

            // Register a metric with the attribute
            let counter = Counter::<u64>::default();
            let _epoch5 = ctx_epoch5.register("votes", "vote count", counter.clone());
            counter.inc();

            // Encode and verify the attribute appears as a label
            let buffer = context.encode();
            assert!(
                buffer.contains("consensus_votes_total{epoch=\"e5\"} 1"),
                "Expected metric with epoch attribute, got: {}",
                buffer
            );

            // Create context with different epoch attribute (same metric name)
            let ctx_epoch6 = context.child("consensus").with_attribute("epoch", "e6");
            let counter2 = Counter::<u64>::default();
            let _epoch6 = ctx_epoch6.register("votes", "vote count", counter2.clone());
            counter2.inc();
            counter2.inc();

            // Both should appear in encoded output with canonical format (single HELP/TYPE)
            let buffer = context.encode();
            assert!(
                buffer.contains("consensus_votes_total{epoch=\"e5\"} 1"),
                "Expected metric with epoch=e5, got: {}",
                buffer
            );
            assert!(
                buffer.contains("consensus_votes_total{epoch=\"e6\"} 2"),
                "Expected metric with epoch=e6, got: {}",
                buffer
            );

            // Verify canonical format: HELP and TYPE should appear exactly once
            assert_eq!(
                buffer.matches("# HELP consensus_votes").count(),
                1,
                "HELP should appear exactly once, got: {}",
                buffer
            );
            assert_eq!(
                buffer.matches("# TYPE consensus_votes").count(),
                1,
                "TYPE should appear exactly once, got: {}",
                buffer
            );

            // Multiple attributes
            let ctx_multi = context
                .child("engine")
                .with_attribute("region", "us")
                .with_attribute("instance", "i1");
            let counter3 = Counter::<u64>::default();
            let _multi = ctx_multi.register("requests", "request count", counter3.clone());
            counter3.inc();

            let buffer = context.encode();
            assert!(
                buffer.contains("engine_requests_total{instance=\"i1\",region=\"us\"} 1"),
                "Expected metric with sorted attributes, got: {}",
                buffer
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_attribute_with_nested_label<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Create context with attribute, then nest a label
            let ctx = context
                .child("orchestrator")
                .with_attribute("epoch", "e5")
                .child("engine");

            // Register a metric
            let counter = Counter::<u64>::default();
            let _registered = ctx.register("votes", "vote count", counter.clone());
            counter.inc();

            // Verify the attribute is preserved through the nested label
            let buffer = context.encode();
            assert!(
                buffer.contains("orchestrator_engine_votes_total{epoch=\"e5\"} 1"),
                "Expected metric with preserved epoch attribute, got: {}",
                buffer
            );

            // Multiple levels of nesting with attributes at different levels
            let ctx2 = context
                .child("outer")
                .with_attribute("region", "us")
                .child("middle")
                .with_attribute("az", "east")
                .child("inner");

            let counter2 = Counter::<u64>::default();
            let _registered2 = ctx2.register("requests", "request count", counter2.clone());
            counter2.inc();
            counter2.inc();

            let buffer = context.encode();
            assert!(
                buffer.contains("outer_middle_inner_requests_total{az=\"east\",region=\"us\"} 2"),
                "Expected metric with all attributes preserved and sorted, got: {}",
                buffer
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_attributes_isolated_between_contexts<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Create two separate sub-contexts, each with their own attribute
            let ctx_a = context.child("component_a").with_attribute("epoch", 1);
            let ctx_b = context.child("component_b").with_attribute("epoch", 2);

            // Register metrics in ctx_a
            let c1 = Counter::<u64>::default();
            let _ctx_a_requests = ctx_a.register("requests", "help", c1);

            // Register metrics in ctx_b
            let c2 = Counter::<u64>::default();
            let _ctx_b_requests = ctx_b.register("requests", "help", c2);

            // Register another metric in ctx_a AFTER ctx_b was used
            let c3 = Counter::<u64>::default();
            let _ctx_a_errors = ctx_a.register("errors", "help", c3);

            let output = context.encode();

            // ctx_a metrics should only have epoch=1
            assert!(
                output.contains("component_a_requests_total{epoch=\"1\"} 0"),
                "ctx_a requests should have epoch=1: {output}"
            );
            assert!(
                output.contains("component_a_errors_total{epoch=\"1\"} 0"),
                "ctx_a errors should have epoch=1: {output}"
            );
            assert!(
                !output.contains("component_a_requests_total{epoch=\"2\"}"),
                "ctx_a requests should not have epoch=2: {output}"
            );

            // ctx_b metrics should only have epoch=2
            assert!(
                output.contains("component_b_requests_total{epoch=\"2\"} 0"),
                "ctx_b should have epoch=2: {output}"
            );
            assert!(
                !output.contains("component_b_requests_total{epoch=\"1\"}"),
                "ctx_b should not have epoch=1: {output}"
            );
        });
    }

    /// Regression test for https://github.com/commonwarexyz/monorepo/issues/3485.
    ///
    /// Verifies the documented guarantee that runtime task metrics ignore context
    /// attributes: spawning with a varying `with_attribute` (as the marshaled
    /// consensus code does for each round) must not create per-value entries in
    /// `runtime_tasks_spawned` / `runtime_tasks_running`.
    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_spawn_attribute_cardinality<R: Runner>(#[case] runner: R)
    where
        R::Context: Spawner + Metrics + Clock,
    {
        runner.start(|context| async move {
            const ROUNDS: u64 = 128;

            let mut handles = Vec::with_capacity(ROUNDS as usize);
            for round in 0..ROUNDS {
                let handle = context
                    .child("deferred_verify")
                    .with_attribute("round", round)
                    .spawn(move |_| async move { round });
                handles.push(handle);
            }
            for (expected, handle) in handles.into_iter().enumerate() {
                assert_eq!(handle.await.expect("task failed"), expected as u64);
            }

            // handle.await resolves when the task's output is ready, but
            // the running-gauge decrement fires on task-struct drop which
            // may lag slightly. Yield to the executor so it can run cleanup.
            while count_running_tasks(&context, "deferred_verify") > 0 {
                context.sleep(Duration::from_millis(10)).await;
            }
            let buffer = context.encode();

            // Count occurrences of each runtime task metric for our label. If
            // attributes were incorrectly folded into the task family key, we
            // would see ROUNDS distinct time series instead of one.
            let spawned_lines = buffer
                .lines()
                .filter(|line| {
                    line.starts_with("runtime_tasks_spawned_total{")
                        && line.contains("name=\"deferred_verify\"")
                })
                .count();
            let running_lines = buffer
                .lines()
                .filter(|line| {
                    line.starts_with("runtime_tasks_running{")
                        && line.contains("name=\"deferred_verify\"")
                })
                .count();
            assert_eq!(
                spawned_lines, 1,
                "expected exactly 1 runtime_tasks_spawned entry for deferred_verify, got {spawned_lines}: {buffer}",
            );
            assert_eq!(
                running_lines, 1,
                "expected exactly 1 runtime_tasks_running entry for deferred_verify, got {running_lines}: {buffer}",
            );

            // The single spawned-counter entry should reflect every round.
            let spawned_value = format!(
                "runtime_tasks_spawned_total{{name=\"deferred_verify\",kind=\"Task\",execution=\"Shared\"}} {ROUNDS}"
            );
            assert!(
                buffer.contains(&spawned_value),
                "expected accumulated spawned counter `{spawned_value}`, got: {buffer}",
            );
            let running_value = "runtime_tasks_running{name=\"deferred_verify\",kind=\"Task\",execution=\"Shared\"} 0";
            assert!(
                buffer.contains(running_value),
                "expected running gauge to return to 0, got: {buffer}",
            );

            // The per-round attribute must not surface on task metrics (the
            // task `Label` does not include context attributes).
            assert!(
                !buffer
                    .lines()
                    .any(|line| line.starts_with("runtime_tasks_")
                        && line.contains("round=")),
                "task metrics must not carry `round` attribute: {buffer}",
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_attributes_sorted_deterministically<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Create two contexts with same attributes but different order
            let ctx_ab = context
                .child("service")
                .with_attribute("region", "us")
                .with_attribute("env", "prod");

            let ctx_ba = context
                .child("service")
                .with_attribute("env", "prod")
                .with_attribute("region", "us");

            // Register via first context
            let c1 = Counter::<u64>::default();
            let _requests = ctx_ab.register("requests", "help", c1.clone());
            c1.inc();

            // Register via second context - same attributes, different metric
            let c2 = Counter::<u64>::default();
            let _errors = ctx_ba.register("errors", "help", c2.clone());
            c2.inc();
            c2.inc();

            let output = context.encode();

            // Both should have the same label order (alphabetically sorted: env, region)
            assert!(
                output.contains("service_requests_total{env=\"prod\",region=\"us\"} 1"),
                "requests should have sorted labels: {output}"
            );
            assert!(
                output.contains("service_errors_total{env=\"prod\",region=\"us\"} 2"),
                "errors should have sorted labels: {output}"
            );

            // Should NOT have reverse order
            assert!(
                !output.contains("region=\"us\",env=\"prod\""),
                "should not have unsorted label order: {output}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_nested_labels_with_attributes<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            // Service A: plain, no nested labels
            let svc_a = context.child("service_a");

            // Service A with attribute (same top-level label, different context)
            let svc_a_v2 = context.child("service_a").with_attribute("version", 2);

            // Service B with nested label: service_b_worker
            let svc_b_worker = context.child("service_b").child("worker");

            // Service B with nested label AND attribute
            let svc_b_worker_shard = context
                .child("service_b")
                .child("worker")
                .with_attribute("shard", 99);

            // Service B different nested label: service_b_manager
            let svc_b_manager = context.child("service_b").child("manager");

            // Service C: plain, proves no cross-service contamination
            let svc_c = context.child("service_c");

            // Register metrics in all contexts
            let c1 = Counter::<u64>::default();
            let _svc_a = svc_a.register("requests", "help", c1);

            let c2 = Counter::<u64>::default();
            let _svc_a_v2 = svc_a_v2.register("requests", "help", c2);

            let c3 = Counter::<u64>::default();
            let _svc_b_worker = svc_b_worker.register("tasks", "help", c3);

            let c4 = Counter::<u64>::default();
            let _svc_b_worker_shard = svc_b_worker_shard.register("tasks", "help", c4);

            let c5 = Counter::<u64>::default();
            let _svc_b_manager = svc_b_manager.register("decisions", "help", c5);

            let c6 = Counter::<u64>::default();
            let _svc_c = svc_c.register("requests", "help", c6);

            let output = context.encode();

            // Service A plain and attributed both exist independently
            assert!(
                output.contains("service_a_requests_total 0"),
                "svc_a plain should exist: {output}"
            );
            assert!(
                output.contains("service_a_requests_total{version=\"2\"} 0"),
                "svc_a_v2 should have version=2: {output}"
            );

            // Service B worker: plain and attributed versions
            assert!(
                output.contains("service_b_worker_tasks_total 0"),
                "svc_b_worker plain should exist: {output}"
            );
            assert!(
                output.contains("service_b_worker_tasks_total{shard=\"99\"} 0"),
                "svc_b_worker_shard should have shard=99: {output}"
            );

            // Service B manager: no attributes
            assert!(
                output.contains("service_b_manager_decisions_total 0"),
                "svc_b_manager should have no attributes: {output}"
            );
            assert!(
                !output.contains("service_b_manager_decisions_total{"),
                "svc_b_manager should have no attributes at all: {output}"
            );

            // Service C: no attributes, no contamination
            assert!(
                output.contains("service_c_requests_total 0"),
                "svc_c should have no attributes: {output}"
            );
            assert!(
                !output.contains("service_c_requests_total{"),
                "svc_c should have no attributes at all: {output}"
            );

            // Cross-contamination checks
            assert!(
                !output.contains("service_b_manager_decisions_total{shard="),
                "svc_b_manager should not have shard: {output}"
            );
            assert!(
                !output.contains("service_a_requests_total{shard="),
                "svc_a should not have shard: {output}"
            );
            assert!(
                !output.contains("service_c_requests_total{version="),
                "svc_c should not have version: {output}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_metrics_family_with_attributes<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            #[derive(Clone, Debug, Hash, PartialEq, Eq, EncodeLabelSet)]
            struct RequestLabels {
                method: String,
                status: u16,
            }

            // Create context with attribute
            let ctx = context
                .child("api")
                .with_attribute("region", "us_east")
                .with_attribute("env", "prod");

            // Register a Family metric
            let requests: Family<RequestLabels, Counter<u64>> = Family::default();
            let _requests = ctx.register("requests", "HTTP requests", requests.clone());

            // Increment counters for different label combinations
            requests
                .get_or_create(&RequestLabels {
                    method: "GET".to_string(),
                    status: 200,
                })
                .inc();
            requests
                .get_or_create(&RequestLabels {
                    method: "POST".to_string(),
                    status: 201,
                })
                .inc();
            requests
                .get_or_create(&RequestLabels {
                    method: "GET".to_string(),
                    status: 404,
                })
                .inc();

            let output = context.encode();

            // Context attributes appear first (alphabetically sorted), then Family labels
            // Context attributes: env="prod", region="us_east"
            // Family labels: method, status
            assert!(
                output.contains(
                    "api_requests_total{env=\"prod\",region=\"us_east\",method=\"GET\",status=\"200\"} 1"
                ),
                "GET 200 should have merged labels: {output}"
            );
            assert!(
                output.contains(
                    "api_requests_total{env=\"prod\",region=\"us_east\",method=\"POST\",status=\"201\"} 1"
                ),
                "POST 201 should have merged labels: {output}"
            );
            assert!(
                output.contains(
                    "api_requests_total{env=\"prod\",region=\"us_east\",method=\"GET\",status=\"404\"} 1"
                ),
                "GET 404 should have merged labels: {output}"
            );

            // Create another context WITHOUT attributes to verify isolation
            let ctx_plain = context.child("api_plain");
            let plain_requests: Family<RequestLabels, Counter<u64>> = Family::default();
            let _plain_requests =
                ctx_plain.register("requests", "HTTP requests", plain_requests.clone());

            plain_requests
                .get_or_create(&RequestLabels {
                    method: "DELETE".to_string(),
                    status: 204,
                })
                .inc();

            let output = context.encode();

            // Plain context should have Family labels but no context attributes
            assert!(
                output.contains("api_plain_requests_total{method=\"DELETE\",status=\"204\"} 1"),
                "plain DELETE should have only family labels: {output}"
            );
            assert!(
                !output.contains("api_plain_requests_total{env="),
                "plain should not have env attribute: {output}"
            );
            assert!(
                !output.contains("api_plain_requests_total{region="),
                "plain should not have region attribute: {output}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_register_and_encode<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            let counter =
                context
                    .child("engine")
                    .register("votes", "vote count", Counter::<u64>::default());
            counter.inc();

            let buffer = context.encode();
            assert!(
                buffer.contains("engine_votes_total 1"),
                "registered metric should appear in encode: {buffer}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_register_drop_removes_metrics<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            let permanent = context.child("permanent").register(
                "counter",
                "permanent counter",
                Counter::<u64>::default(),
            );
            permanent.inc();

            let counter =
                context
                    .child("engine")
                    .register("votes", "vote count", Counter::<u64>::default());
            counter.inc();

            let buffer = context.encode();
            assert!(buffer.contains("permanent_counter_total 1"));
            assert!(buffer.contains("engine_votes_total 1"));

            drop(counter);

            let buffer = context.encode();
            assert!(
                buffer.contains("permanent_counter_total 1"),
                "other registered metrics should survive handle drop: {buffer}"
            );
            assert!(
                !buffer.contains("engine_votes"),
                "metric should be removed after handle drop: {buffer}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_register_with_attributes<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            let epoch1 = context.child("engine").with_attribute("epoch", 1).register(
                "votes",
                "vote count",
                Counter::<u64>::default(),
            );
            epoch1.inc();

            let epoch2 = context.child("engine").with_attribute("epoch", 2).register(
                "votes",
                "vote count",
                Counter::<u64>::default(),
            );
            epoch2.inc();
            epoch2.inc();

            let buffer = context.encode();
            assert!(buffer.contains("engine_votes_total{epoch=\"1\"} 1"));
            assert!(buffer.contains("engine_votes_total{epoch=\"2\"} 2"));

            assert_eq!(
                buffer.matches("# HELP engine_votes").count(),
                1,
                "HELP should appear once: {buffer}"
            );
            assert_eq!(
                buffer.matches("# TYPE engine_votes").count(),
                1,
                "TYPE should appear once: {buffer}"
            );

            drop(epoch1);
            let buffer = context.encode();
            assert!(
                !buffer.contains("epoch=\"1\""),
                "epoch 1 should be gone: {buffer}"
            );
            assert!(buffer.contains("engine_votes_total{epoch=\"2\"} 2"));

            drop(epoch2);
            let buffer = context.encode();
            assert!(
                !buffer.contains("engine_votes"),
                "all epoch metrics should be gone: {buffer}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_reregister_after_drop<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            let votes = context.child("engine").with_attribute("epoch", 1).register(
                "votes",
                "vote count",
                Counter::<u64>::default(),
            );
            drop(votes);

            let replacement = context.child("engine").with_attribute("epoch", 1).register(
                "votes",
                "vote count",
                Counter::<u64>::default(),
            );
            drop(replacement);
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_register_clone_keeps_metric_alive<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            let registered =
                context
                    .child("engine")
                    .register("votes", "vote count", Counter::<u64>::default());
            registered.inc();
            let clone = registered.clone();

            let buffer = context.encode();
            assert!(
                buffer.contains("engine_votes_total 1"),
                "metric should remain registered while any handle exists: {buffer}"
            );

            drop(registered);
            let buffer = context.encode();
            assert!(
                buffer.contains("engine_votes_total 1"),
                "metric should survive while clone is retained: {buffer}"
            );

            drop(clone);
            let buffer = context.encode();
            assert!(
                !buffer.contains("engine_votes"),
                "metric should be removed when all handle clones are dropped: {buffer}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_encode_single_eof<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        runner.start(|context| async move {
            let root_counter = context.register("root", "root metric", Counter::<u64>::default());
            root_counter.inc();

            let child =
                context
                    .child("engine")
                    .register("ops", "child metric", Counter::<u64>::default());
            child.inc();

            let buffer = context.encode();
            assert!(
                buffer.contains("root_total 1"),
                "root metric missing: {buffer}"
            );
            assert!(
                buffer.contains("engine_ops_total 1"),
                "child metric missing: {buffer}"
            );
            assert_eq!(
                buffer.matches("# EOF").count(),
                1,
                "expected exactly one EOF marker: {buffer}"
            );
            assert!(
                buffer.ends_with("# EOF\n"),
                "EOF must be the last line: {buffer}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_family_with_attributes<R: Runner>(#[case] runner: R)
    where
        R::Context: Metrics,
    {
        #[derive(Clone, Debug, Hash, PartialEq, Eq)]
        struct Peer {
            name: String,
        }
        impl EncodeLabelSet for Peer {
            fn encode(&self, encoder: &mut LabelSetEncoder<'_>) -> Result<(), std::fmt::Error> {
                let mut label = encoder.encode_label();
                let mut key = label.encode_label_key()?;
                EncodeLabelKey::encode(&"peer", &mut key)?;
                let mut value = key.encode_label_value()?;
                EncodeLabelValue::encode(&self.name.as_str(), &mut value)?;
                value.finish()
            }
        }

        runner.start(|context| async move {
            let family = context
                .child("batcher")
                .with_attribute("epoch", 1)
                .register(
                    "votes",
                    "votes per peer",
                    Family::<Peer, Counter>::default(),
                );
            family
                .get_or_create(&Peer {
                    name: "alice".into(),
                })
                .inc();
            family.get_or_create(&Peer { name: "bob".into() }).inc();

            let buffer = context.encode();
            assert!(
                buffer.contains("batcher_votes_total{epoch=\"1\",peer=\"alice\"} 1"),
                "family with attributes should combine labels: {buffer}"
            );
            assert!(
                buffer.contains("batcher_votes_total{epoch=\"1\",peer=\"bob\"} 1"),
                "family with attributes should combine labels: {buffer}"
            );

            drop(family);
            let buffer = context.encode();
            assert!(
                !buffer.contains("batcher_votes"),
                "family metrics should be removed: {buffer}"
            );
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_strategy<R: Runner>(#[case] runner: R)
    where
        R::Context: Strategizer + Metrics,
    {
        runner.start(|context| async move {
            // Create a strategy with a parallelism of 4.
            let strategy = context.child("pool").strategy(NZUsize!(4));
            assert_eq!(strategy.manual().parallelism(), 4);

            // Use the strategy to sum a vector of numbers.
            let sum = strategy.fold(0..10000, || 0i32, |acc, n| acc + n, |a, b| a + b);
            assert_eq!(sum, 10000 * 9999 / 2);
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default())]
    #[case::tokio(tokio::Runner::default())]
    fn test_nested_strategy_runs_inline<R: Runner>(#[case] runner: R)
    where
        R::Context: Strategizer + Metrics,
    {
        runner.start(|context| async move {
            let strategy = context.child("pool").strategy(NZUsize!(1)).manual();

            let output = strategy
                .spawn(|strategy| strategy.map_collect_vec(0..2, |i| i + 1))
                .await;

            assert_eq!(output, vec![1, 2]);
        });
    }

    #[rstest]
    #[case::deterministic(deterministic::Runner::default(), 4096, 64)]
    #[case::deterministic_custom(
        deterministic::Runner::new(
            deterministic::Config::default()
                .with_network_buffer_pool_config(
                    BufferPoolConfig::for_network().with_max_per_class(NZU32!(64)),
                )
                .with_storage_buffer_pool_config(
                    BufferPoolConfig::for_storage().with_max_per_class(NZU32!(8)),
                ),
        ),
        64,
        8
    )]
    #[case::tokio(tokio::Runner::default(), 4096, 64)]
    #[case::tokio_custom(
        tokio::Runner::new(
            tokio::Config::default()
                .with_network_buffer_pool_config(
                    BufferPoolConfig::for_network().with_max_per_class(NZU32!(64)),
                )
                .with_storage_buffer_pool_config(
                    BufferPoolConfig::for_storage().with_max_per_class(NZU32!(8)),
                ),
        ),
        64,
        8
    )]
    fn test_buffer_pooler<R: Runner>(
        #[case] runner: R,
        #[case] expected_network_max_per_class: u32,
        #[case] expected_storage_max_per_class: u32,
    ) where
        R::Context: BufferPooler,
    {
        runner.start(|context| async move {
            // Verify network pool is accessible and works (cache-line aligned)
            let net_buf = context.network_buffer_pool().try_alloc(1024).unwrap();
            assert!(net_buf.capacity() >= 1024);

            // Verify storage pool is accessible and works (page-aligned)
            let storage_buf = context.storage_buffer_pool().try_alloc(1024).unwrap();
            assert!(storage_buf.capacity() >= 4096);

            // Verify pools have expected configurations
            assert!(
                context
                    .network_buffer_pool()
                    .config()
                    .size_classes()
                    .all(|class| class.max_buffers.get() == expected_network_max_per_class)
            );
            assert!(
                context
                    .storage_buffer_pool()
                    .config()
                    .size_classes()
                    .all(|class| class.max_buffers.get() == expected_storage_max_per_class)
            );
        });
    }
}
