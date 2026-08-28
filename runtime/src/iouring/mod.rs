//! A runtime whose workers pair a single-threaded executor with an io_uring
//! event loop.
//!
//! The thread that calls [crate::Runner::start] runs the root worker. Every
//! dedicated task and blocking shared task runs as the root of another worker
//! on its own thread. Each worker owns one ring shared by its executor, storage
//! adapter, and network adapter. Its thread alternates between polling tasks
//! and driving ring-backed I/O, then parks when neither side can make progress.
//!
//! This module is enabled by the `iouring` feature and is only available on Linux.
//!
//! # Kernel Requirements
//!
//! This runtime requires Linux kernel 6.1 or newer. Each worker creates its
//! ring with `IORING_SETUP_SINGLE_ISSUER` and `IORING_SETUP_DEFER_TASKRUN` and
//! remains its only submitter. The internal `eventfd` wake path also relies on
//! io_uring multishot poll (Linux 5.13 or newer).
//!
//! # Worker Affinity
//!
//! Every task spawned with [crate::Spawner::dedicated] (or [crate::Spawner::shared]
//! with `blocking == true`) runs as the root of a worker on its own thread with its
//! own ring. Ring-bound resources ([crate::Blob]s, [crate::Sink]s, [crate::Stream]s,
//! [crate::Listener]s, and in-flight operation futures) are bound to the worker that
//! created them. Network and storage operations remain worker-affine even when
//! a particular call completes synchronously or from cached data. Calling one
//! from another worker panics with "io_uring runtime operations must run on the
//! runtime thread". Inside a spawned task, [Config::with_catch_panics] controls
//! whether that panic becomes [Error::Exited](crate::Error::Exited) or unwinds
//! [crate::Runner::start] after cleanup. Root and ordinary runtime-infrastructure
//! panics likewise unwind
//! `start` after mandatory cleanup. A panic during mandatory ring drain aborts
//! the process because unwinding could release resources still referenced by
//! the kernel. Moving a blob or socket into a dedicated task works on the tokio
//! runtime but not here. This trade lets the op path avoid locks.
//! Move plain data between workers and open resources on the worker that uses
//! them.
//!
//! Task handles, contexts (spawning, sleeping, stopping), and channels may cross
//! workers. Ring-bound resource values may also be dropped on another worker.
//! Pending operation and ticket state is routed back to its owner so kernel
//! resources remain alive until completion. An idle resource's descriptor may
//! instead close on the thread that drops its final owner.
//!
//! # Request Lifecycle
//!
//! A request changes owners as it moves from a task to the kernel and back:
//!
//! ```text
//! task future owns Request
//!          |
//!          v
//! DriverHandle admission -- no unreserved capacity --> capacity FIFO
//!          |                                             |
//!          |<---------------- reserved waiter slot ------+
//!          v
//! waiter owns Request --> backlog --> SQE --> io_uring --> operation CQE
//!                                              |                 |
//!                                              |                 +-- nonterminal --> backlog
//!                                              |                 |
//!                                              |                 +-- Op output stays in waiter
//!                                              |                 |
//!                                              |                 `-- Ticket output published
//!                                              |                     before waiter recycle
//!                                              |
//! foreign drop --> orphan mailbox --> owner worker --> cancel, detach, or free
//! ```
//!
//! The waiter retains every resource the kernel may reference until the
//! original operation CQE arrives. A cancel CQE acknowledges cancellation but
//! does not retire those resources. RawWaker drop and wake callbacks run only
//! after the driver releases its mutable operation-state borrow.
//!
//! # Timeout Handling
//!
//! Requests can optionally carry an absolute deadline. When present:
//!
//! - The capacity FIFO owns the absolute deadline before waiter admission
//! - A deadline that expires before admission completes locally without a waiter
//! - First staging transfers the deadline to the worker's userspace timing wheel
//! - Requests that still have an SQE in flight submit an async-cancel SQE on expiry
//! - Requests parked only in the backlog time out locally without cancel SQEs
//! - Timeouts apply to the whole logical request, not individual SQEs
//! - If the original op CQE completes the whole request, the caller sees success
//! - If the original op CQE only makes partial/retryable progress after timeout, the caller
//!   sees timeout and no follow-up SQE is issued
//!
//! # Shutdown Process
//!
//! Each worker tears down and drains its own ring. The root worker drains before
//! [crate::Runner::start] closes the worker registry and joins the remaining
//! worker threads, which independently perform the same teardown:
//!
//! 1. The worker closes timers and task registration, then drops its tasks
//! 2. Unadmitted requests and capacity registrations are released locally
//! 3. Admitted requests whose observers were dropped are wound down. Cancelable
//!    requests are cancelled, while writes and data syncs detach and continue
//!    to preserve their durability contract
//! 4. New admissions fail with their kind-specific error
//! 5. The drain waits for all progressing requests to complete or retire,
//!    including pending tickets retained outside the torn-down task graph
//! 6. If `shutdown_timeout` is configured, it triggers cancellation after a
//!    grace period, but kernel retirement remains unbounded
//! 7. Ready escaped-ticket results survive in the ticket arena until poll or drop
//!
//! # Liveness Model
//!
//! Each worker's ring size also bounds its waiter-backed operations, not
//! dependency closure. New submissions park on a FIFO capacity wait list when
//! no unreserved waiter slot is available. Freeing slots grants them to queued
//! admissions in order, and each grant stays reserved until its owner polls or
//! cancels. Fresh submissions cannot consume capacity reserved for older attempts.
//! Already-admitted requests may still be restaged ahead of fresh admissions according
//! to the driver's submission policy.
//!
//! If every waiter-backed request depends on work that cannot be admitted because the table
//! is full, the loop cannot make progress until an admitted request completes or is cancelled.
//!
//! Concrete example with `cfg.size = 2`:
//!
//! 1. Queue `read(fd1)`, `read(fd2)`, `write(fd1)`, `write(fd2)` in that order.
//! 2. The loop stages the first two reads and reaches waiter capacity.
//! 3. If each read depends on its corresponding write being submitted through the same loop, both
//!    reads remain blocked.
//! 4. The writes stay queued behind the capacity limit, so no completion is produced and the loop
//!    cannot free capacity on its own.
//!
//! The runtime cannot infer dependency relationships between arbitrary queued and admitted
//! requests, so it cannot implement dependency-aware admission (and doing so generically would
//! add substantial overhead).
//!
//! The practical way to recover from this condition is cancellation via per-request timeouts.
//! When timed-out requests are cancelled, waiter capacity is eventually released and
//! queued requests can be staged. Without cancellation, liveness depends on workload structure:
//! callers must avoid submission patterns where admitted requests require later queued requests
//! to run.
//!
//! Operational guidance:
//!
//! - Workloads that may create causal dependencies across queued and admitted requests must use
//!   per-request timeouts.
//! - If cancellation is disabled, callers must guarantee that admitted requests never depend on
//!   later queued requests, otherwise the loop can deadlock.
//! - Ready detached tickets do not count toward waiter capacity. Their waiter is recycled before
//!   the ticket waker runs, so retaining a completed accept or sync ticket cannot block admission.
//! - A timed request's deadline includes time spent waiting for capacity. The event loop parks no
//!   longer than the earliest admission or active-request deadline, so capacity saturation cannot
//!   hide timeout progress.

mod driver;
#[cfg(test)]
pub(crate) use driver::testing;
pub(crate) use driver::{AcceptTicket, Cache, DriverHandle};
pub use driver::{MAX_RING_SIZE, SpinnerConfig};
mod runtime;
pub use runtime::{Config, Context, Runner};
mod sockaddr;
pub(crate) use sockaddr::RawSocketAddr;
use std::time::Duration;

/// Configuration for an io_uring instance.
/// See `man io_uring`.
#[derive(Clone, Debug)]
pub struct RingConfig {
    /// Requested size of each worker's ring.
    ///
    /// This value is rounded up to the next power of two when constructing
    /// the event loop, so the configured in-flight waiter capacity matches the
    /// effective ring sizing behavior. Linux permits at most 32,768 submission
    /// queue entries, so the rounded size must not exceed [`MAX_RING_SIZE`].
    /// Larger rounded sizes panic during construction.
    pub size: u32,
    /// Grace before the io_uring event loop requests cancellation of every
    /// request still outstanding during shutdown drain.
    ///
    /// If None, the event loop will wait indefinitely for in-flight requests
    /// to complete during that drain phase. In this case, the caller should be
    /// careful to ensure that submitted requests will eventually complete.
    ///
    /// If Some, the grace is measured from drain entry across completion and
    /// orphan processing, staging, callbacks, retries, and kernel waits. Every
    /// request still outstanding when it expires is cancelled exactly once.
    /// The drain then waits for the kernel to retire the cancelled requests: a
    /// request is never dropped while the kernel may still reference its
    /// buffers, so operations that cannot be cancelled (e.g. an executing disk
    /// write) are awaited after the grace. This is not a total shutdown bound.
    pub shutdown_timeout: Option<Duration>,
    /// Tick granularity used by the userspace timeout wheel.
    ///
    /// Smaller values increase timing precision but increase wakeup and wheel
    /// processing frequency. Must be non-zero.
    ///
    /// The tick also bounds the wheel size. Its horizon is derived from the
    /// maximum configured network timeout, and its slot count rounds up to a
    /// power of two above `ceil(horizon / tick) + 1`. The wheel is capped at
    /// 1,048,576 slots, so a smaller tick supports a shorter derived horizon
    /// before the startup panic (about 87 minutes at the default 5 ms tick).
    /// At the cap the wheel holds about 28 MiB of fixed metadata per worker on
    /// 64-bit builds. Larger horizons require a coarser tick.
    pub timeout_wheel_tick: Duration,
    /// Adaptive idle spinner configuration.
    pub idle_spinner: SpinnerConfig,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            size: 128,
            shutdown_timeout: None,
            timeout_wheel_tick: Duration::from_millis(5),
            idle_spinner: SpinnerConfig::default(),
        }
    }
}
