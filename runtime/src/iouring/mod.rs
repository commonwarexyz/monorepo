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
//! # Event Loop
//!
//! The event loop provides a high-level interface for submitting logical requests to Linux's
//! io_uring subsystem and receiving their results. The design centers around a single event loop
//! that manages the submission queue (SQ) and completion queue (CQ) of an io_uring instance.
//!
//! Work is submitted thread-locally: op futures stage requests directly into the loop's
//! shared state (a waiter slab plus a backlog FIFO) while they are polled on the runtime
//! thread, and completions are parked in the waiter slot until the owning future takes
//! them. There are no channels and no per-op allocations on this path. The event loop
//! blocks either in userspace futex wait (when the ring is truly idle) or in
//! `io_uring_enter` (when the ring has active waiters), and is woken by:
//! - normal CQE progress in the ring
//! - futex wake when a task is woken from another thread while fully idle
//! - `eventfd` readiness when a task is woken from another thread while blocked in
//!   `submit_and_wait`
//!
//! The runtime executor drives the loop by interleaving a non-blocking `turn` (drain
//! completions, advance deadlines, stage and flush submissions) and a blocking `park`
//! with task polling on the runtime thread. Because staging happens only during task
//! polls, every submission is followed by a `turn` before the executor can park.
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
//! own ring. Ring-bound resources — [crate::Blob]s, [crate::Sink]s, [crate::Stream]s,
//! [crate::Listener]s, and in-flight operation futures — are bound to the worker that
//! created them: **using one from another worker panics** with "io_uring runtime
//! operations must run on the runtime thread". Like any other task panic, it is
//! caught by the using task's wrapper and resolves the task's handle with
//! [Error::Exited](crate::Error::Exited) when the runtime is configured with
//! `catch_panics(true)`; with the default `catch_panics(false)` the panic is
//! forwarded to the root and unwinds [crate::Runner::start]. Moving a blob or
//! socket into a dedicated task works on the tokio runtime but not here; this is a deliberate
//! trade — thread affinity is what lets the op path run without locks. Move plain
//! data between workers and open resources on the worker that uses them.
//!
//! Everything else crosses workers freely: task handles, contexts (spawning,
//! sleeping, stopping), channels, and *dropping* a ring-bound resource (foreign
//! drops are routed back to the owning worker's loop and released there).
//!
//! # Architecture
//!
//! ## Event Loop
//!
//! Each pass of the event loop (driven by the executor's `turn`/`park` cycle):
//! 1. Processes io_uring completion queue entries (CQEs), including internal wake CQEs
//! 2. Advances userspace deadlines
//! 3. Builds and submits SQEs for requests admitted into the backlog by op futures
//! 4. Handles partial progress and retryable errors by requeuing requests
//! 5. Parks terminal results in the waiter slot and wakes the awaiting task
//!
//! ## Request Flow
//!
//! ```text
//! Data path:
//!   Op future poll -> Driver (slab insert + backlog FIFO) -> IoUringLoop -> SQE -> io_uring
//!   Op future poll <- parked Output in slot <- IoUringLoop <- CQE <- io_uring
//!
//! Wake paths (cross-thread task wakes only):
//!   Foreign thread --futex wake--> packed wake state --> IoUringLoop
//!   Foreign thread --write(eventfd)--> wake_fd --POLLIN CQE (WAKE_USER_DATA)--> IoUringLoop
//!
//! Loop behavior:
//!   1) Drain CQEs.
//!   2) Advance timeouts.
//!   3) Rarely rearm wake polling, then stage cancels and backlog requests
//!      into SQ (scheduling deadlines at first staging).
//!   4) If work is pending or active waiters remain, submit and possibly block in
//!      io_uring_enter until a CQE (data or wake) arrives.
//!   5) If the ring is fully idle, arm the shared wake word and sleep in futex
//!      wait until another thread latches an out-of-band wake.
//! ```
//!
//! ## Work Tracking
//!
//! Each admitted request is assigned a waiter id that serves as the `user_data` field in its
//! SQEs. The loop state maintains a flat `Waiters` store where each slot maps to a
//! request that owns all resources (buffers, FDs, progress state) needed for the
//! request's lifetime, plus the waker of the awaiting task and, after completion,
//! the parked terminal result.
//!
//! ## Timeout Handling
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
//! ## Submission Policy
//!
//! A logical request may need multiple SQEs before it completes. Fresh admissions and
//! requeued requests share one backlog (the FIFO of admitted requests whose next SQE the
//! loop must build), and the loop stages work in this order:
//! 1. Rarely, a wake poll rearm SQE when a prior multishot wake CQE ended the
//!    existing poll registration.
//! 2. Cancellation SQEs for timed-out or drop-cancelled requests.
//! 3. Staged-queue requests, until SQ capacity is hit.
//!
//! When the waiter slab is full, op futures park on a capacity wait list and are all
//! woken whenever a slot frees (a woken future re-registers if it loses the race).
//!
//! ## Wake Handling
//!
//! Cross-thread task wakes (e.g. a timer or channel resolved by a helper thread) use one
//! shared atomic state word plus an internal `eventfd`.
//! - When the loop has no waiters, it sleeps in futex wait on that shared word
//! - When the loop blocks in `submit_and_wait`, it keeps a multishot `PollAdd`
//!   on the internal `eventfd`
//! - Wake CQEs drain `eventfd` readiness and re-install poll when `IORING_CQE_F_MORE`
//!   is not set
//! - A dedicated signalled bit coalesces repeated wake attempts while a wait is armed
//!
//! The wake word also carries a packed submission-sequence protocol (publish and
//! recheck) that this runtime no longer exercises: submissions are staged on the loop
//! thread itself, so no cross-thread submission edge exists. The protocol is retained
//! for a future cross-thread submission path.
//!
//! ## Shutdown Process
//!
//! At teardown (after every task has been dropped, which eagerly cancels their
//! abandoned operations), the runtime closes the driver and drains the loop:
//! 1. New admissions fail with their kind-specific error
//! 2. The drain waits for all progressing requests to complete or be cancelled
//! 3. If `shutdown_timeout` is configured, every request still outstanding when the
//!    budget expires is cancelled, and the drain then waits for the kernel to retire
//!    it (buffers stay owned until then)
//! 4. Parked results owned by escaped tickets survive the drain: they hold no kernel
//!    resources and are reclaimed when their ticket is polled or dropped
//!
//! ## Liveness Model
//!
//! This loop enforces a configured upper bound on in-flight requests. New submissions
//! park on a capacity wait list when the slab is full; freeing a slot wakes every
//! parked admission at once and losers re-register, so ordering among admissions is
//! unspecified (a fresh submission may barge ahead of a long-parked one), and
//! already-admitted requests may be restaged ahead of fresh admissions according to
//! the submission policy above.
//!
//! This implies a bounded-liveness caveat: if all in-flight requests are waiting on operations
//! that are still queued behind the capacity limit, the loop cannot make progress until some
//! in-flight request completes or is canceled.
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
//! The runtime cannot infer dependency relationships between arbitrary queued and in-flight
//! requests, so it cannot implement dependency-aware admission (and doing so generically would
//! add substantial overhead).
//!
//! The practical way to recover from this condition is cancellation via per-request timeouts.
//! When timed-out in-flight requests are canceled, waiter capacity is eventually released and
//! queued requests can be staged. Without cancellation, liveness depends on workload structure:
//! callers must avoid submission patterns where in-flight requests require later queued requests
//! to run.
//!
//! Operational guidance:
//! - Workloads that may create causal dependencies across queued and in-flight requests must use
//!   per-request timeouts.
//! - If cancellation is disabled, callers must guarantee that in-flight requests never depend on
//!   later queued requests, otherwise the loop can deadlock.
//! - Parked terminal results count toward the capacity limit until their ticket is polled or
//!   dropped, and capacity waiters themselves have no deadline protection (deadlines only apply
//!   after admission). A task that retains a completed ticket indefinitely therefore withholds a
//!   slot from waiting admissions, exactly as an unread completion channel did previously.

pub(crate) mod driver;
#[cfg(test)]
pub(crate) use driver::testing;
pub(crate) use driver::{AcceptTicket, Driver, Handle, RawSocketAddr};
pub use driver::{MAX_RING_SIZE, spinner::Config as SpinnerConfig};
mod runtime;
pub use runtime::{Config, Context, Runner};
use std::time::Duration;

/// Configuration for an io_uring instance.
/// See `man io_uring`.
#[derive(Clone, Debug)]
pub struct RingConfig {
    /// Requested size of the ring.
    ///
    /// This value is rounded up to the next power of two when constructing
    /// the event loop, so the configured in-flight waiter capacity matches the
    /// effective ring sizing behavior. After rounding, the maximum allowed size
    /// is [`MAX_RING_SIZE`], larger rounded sizes panic during construction.
    pub size: u32,
    /// If true, use IOPOLL mode.
    pub io_poll: bool,
    /// If true, use single issuer mode.
    /// Warning: when enabled, the same thread that creates the ring must be
    /// the only thread that submits work to it.
    ///
    /// The runtime always enables this: the runtime thread creates the ring
    /// and performs all ring submissions.
    /// See IORING_SETUP_SINGLE_ISSUER in <https://man7.org/linux/man-pages/man2/io_uring_setup.2.html>.
    pub single_issuer: bool,
    /// Maximum request timeout supported by the userspace timeout wheel.
    ///
    /// Deadlines are clamped to this horizon. This value should be set to the
    /// largest expected per-request deadline budget. Must be non-zero, and the
    /// runtime raises it to cover both configured network timeouts.
    ///
    /// The wheel allocates a power of two of slots above
    /// `ceil(horizon / tick) + 1`, capped at 1,048,576 slots: a configuration
    /// that rounds above the cap panics at startup, before allocation. At the
    /// cap the wheel holds about 28 MiB of fixed metadata per worker on 64-bit
    /// builds, and with the default 5 ms [Self::timeout_wheel_tick] the cap
    /// corresponds to a horizon of about 87 minutes. Larger horizons require a
    /// coarser tick.
    pub max_request_timeout: Duration,
    /// The maximum time the io_uring event loop waits for outstanding
    /// requests during the drain phase, after runtime teardown has closed the
    /// driver to new admissions.
    ///
    /// If None, the event loop will wait indefinitely for in-flight requests
    /// to complete during that drain phase. In this case, the caller should be
    /// careful to ensure that submitted requests will eventually complete.
    ///
    /// If Some, every request still outstanding when the budget expires is
    /// cancelled. The drain then waits for the kernel to retire the cancelled
    /// requests: a request is never dropped while the kernel may still
    /// reference its buffers, so operations that cannot be cancelled (e.g. an
    /// executing disk write) are awaited regardless of the budget.
    pub shutdown_timeout: Option<Duration>,
    /// Tick granularity used by the userspace timeout wheel.
    ///
    /// Smaller values increase timing precision but increase wakeup and wheel
    /// processing frequency. Must be non-zero.
    ///
    /// The tick also bounds the wheel size: slots round up to a power of two
    /// above `ceil(horizon / tick) + 1` and are capped at 1,048,576, so a
    /// smaller tick supports a shorter [Self::max_request_timeout] horizon
    /// before the startup panic (about 87 minutes at the default 5 ms tick).
    /// At the cap the wheel holds about 28 MiB of fixed metadata per worker
    /// on 64-bit builds.
    pub timeout_wheel_tick: Duration,
    /// Adaptive idle spinner configuration.
    pub idle_spinner: SpinnerConfig,
}

impl Default for RingConfig {
    fn default() -> Self {
        Self {
            size: 128,
            io_poll: false,
            single_issuer: false,
            max_request_timeout: Duration::from_secs(60),
            shutdown_timeout: None,
            timeout_wheel_tick: Duration::from_millis(5),
            idle_spinner: SpinnerConfig::default(),
        }
    }
}
