//! A single-threaded runtime driven by an io_uring event loop.
//!
//! This module provides a runtime whose executor and I/O driver share one thread: the
//! thread that calls [crate::Runner::start] on [Runner] alternates between polling tasks
//! and operating an io_uring event loop that services all storage and network I/O. When
//! no task is runnable, the executor parks inside the event loop's wait primitives until
//! a completion arrives, a timer fires, or another thread wakes a task.
//!
//! This module is enabled by the `iouring` feature and is only available on Linux.
//!
//! # Kernel Requirements
//!
//! This runtime requires Linux kernel 6.1 or newer: the ring is configured with
//! `IORING_SETUP_SINGLE_ISSUER` and `IORING_SETUP_DEFER_TASKRUN` (the runtime thread
//! creates the ring and is the only submitter). The internal `eventfd` wake path also
//! relies on io_uring multishot poll (Linux 5.13+).
//!
//! # Worker Affinity
//!
//! Every task spawned with [crate::Spawner::dedicated] (or [crate::Spawner::shared]
//! with `blocking == true`) runs as the root of a worker on its own thread with its
//! own ring. Ring-bound resources ([crate::Blob]s, [crate::Sink]s, [crate::Stream]s,
//! [crate::Listener]s, and in-flight operation futures) are bound to the worker that
//! created them: **using one from another worker panics** with "io_uring runtime
//! operations must run on the runtime thread". Like any other task panic, it is
//! caught by the using task's wrapper and resolves the task's handle with
//! [Error::Exited](crate::Error::Exited) when the runtime is configured with
//! `catch_panics(true)`. With the default `catch_panics(false)` the panic is
//! forwarded to the root and unwinds [crate::Runner::start]. Moving a blob or
//! socket into a dedicated task works on the tokio runtime but not here. This is a
//! deliberate trade: thread affinity is what lets the op path run without locks. Move
//! plain data between workers and open resources on the worker that uses them.
//!
//! Task handles, contexts (spawning, sleeping, stopping), and channels may cross
//! workers. Ring-bound resource values may also be dropped on another worker.
//! Pending operation and ticket state is routed back to its owner so kernel
//! resources remain alive until completion. An idle resource's descriptor may
//! instead close on the thread that drops its final owner.
//!
//! # Timeout Handling
//!
//! Requests can optionally carry an absolute deadline. When present:
//! - The loop tracks deadline ticks in a userspace timing wheel, scheduling each
//!   request's deadline at its first staging
//! - Requests whose deadline already expired at first staging complete immediately
//!   with timeout before any SQE is issued
//! - Requests that still have an SQE in flight submit an async-cancel SQE on expiry
//! - Requests parked only in the backlog time out locally without cancel SQEs
//! - Timeouts apply to the whole logical request, not individual SQEs
//! - If the original op CQE completes the whole request, the caller sees success
//! - If the original op CQE only makes partial/retryable progress after timeout, the caller
//!   sees timeout and no follow-up SQE is issued
//!
//! # Shutdown Process
//!
//! At teardown (after every task has been dropped, which eagerly cancels their
//! abandoned operations), the runtime closes the driver and drains the loop:
//! 1. New admissions fail with their kind-specific error
//! 2. The drain waits for all progressing requests to complete or be cancelled
//! 3. If `shutdown_timeout` is configured, it is a cancellation grace measured from
//!    drain entry. Every request still outstanding when the grace expires is cancelled,
//!    then the drain waits for the kernel to retire it (buffers stay owned until then)
//! 4. Ready results owned by escaped tickets survive the drain in the ticket arena:
//!    they hold no kernel resources or waiter slots and are reclaimed when polled or dropped
//!
//! # Liveness Model
//!
//! The ring size bounds waiter-backed operations, not dependency closure. New submissions
//! park on a FIFO capacity wait list when the waiter table is full. Freeing slots grants them
//! to queued admissions in order, and each grant stays reserved until its owner polls
//! or cancels. Fresh submissions cannot consume capacity reserved for older attempts.
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
//! - Workloads that may create causal dependencies across queued and admitted requests must use
//!   per-request timeouts.
//! - If cancellation is disabled, callers must guarantee that admitted requests never depend on
//!   later queued requests, otherwise the loop can deadlock.
//! - Ready detached tickets do not count toward waiter capacity. Their waiter is recycled before
//!   the ticket waker runs, so retaining a completed accept or sync ticket cannot block admission.
//! - A timed request's deadline includes time spent waiting for capacity. The event loop parks no
//!   longer than the earliest admission or active-request deadline, so a full waiter table cannot
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
    /// Requested size of the ring.
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
