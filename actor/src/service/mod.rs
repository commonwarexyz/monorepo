//! Shared service loop primitive for actors.
//!
//! [`Builder`] runs an [`Actor`](crate::Actor) on a managed control loop: a
//! single task that owns the actor and dispatches ingress to its hooks. Each
//! message is declared read-only or read-write by the
//! [`ingress!`](crate::ingress!) declaration that produced it, and the loop
//! gives each class a different execution mode.
//!
//! # Concurrency Model
//!
//! Read-only ingress is dispatched to a pool of pre-spawned read workers,
//! bounded by [`Builder::with_read_concurrency`]. Each handler receives a
//! snapshot of actor state captured when its message was admitted.
//! Consecutive reads admitted without an intervening actor mutation share one
//! snapshot capture. The snapshot must not alias data mutated by lifecycle
//! hooks, which can overlap reads under either fence mode. Under
//! [`FenceMode::Snapshot`], it also must not alias data that a read-write
//! handler can mutate.
//!
//! Read-write ingress runs serially on the control loop itself. While a
//! write runs, no new ingress of either class is admitted.
//!
//! ```text
//!                          +--> read worker (snapshot)
//!                          |
//!   lanes --> control -----+--> read worker (snapshot)
//!             loop         |
//!               |          +--> read worker (snapshot)
//!               |
//!               +--> on_read_write (serial, ordered by FenceMode)
//! ```
//!
//! # Ordering
//!
//! Each read receives the snapshot captured at admission. [`FenceMode`]
//! controls whether a write admitted later waits for that read:
//!
//! - [`FenceMode::Linearizable`] (default) drains every in-flight read before
//!   a write runs. A read admitted before a write completes its response and
//!   handler-owned work before that write executes, so no caller can observe a
//!   pre-write response arrive after the write has been acknowledged. Read
//!   handlers must honor the completion contract on
//!   [`Actor::on_read_only`](crate::Actor::on_read_only). The cost is that one
//!   slow read stalls the write and all ingress behind it.
//! - [`FenceMode::Snapshot`] runs writes immediately, concurrently with
//!   in-flight reads. Reads still respond with the snapshot captured at
//!   admission. With an owned or immutable snapshot, responses remain
//!   self-consistent but can be stale relative to acknowledged writes.
//!
//! Within one lane, messages are dequeued and admitted in enqueue order.
//! Concurrent read-only handlers can complete out of order. Across lanes,
//! selection is declaration-order biased (see [`Builder`]).
//!
//! # Shutdown
//!
//! The control loop observes runtime stop while selecting events, waiting for
//! read capacity or a read fence, and between admissions in a lane batch.
//! Mutable actor hooks are cooperative and can delay that observation. After
//! any stop condition is observed, the service closes its lanes, aborts and
//! joins in-flight read-only handler tasks, then calls
//! [`Actor::on_shutdown`](crate::Actor::on_shutdown). Runtime supervision
//! signals handler descendants to abort but does not join them, so those tasks
//! must be safe to overlap shutdown. Askers owned by aborted handlers observe
//! [`Cancelled`](crate::ingress::Cancelled).
//!
//! # Event Sources
//!
//! Actors that only need mailbox input can use the default
//! [`Actor::next_event`](crate::Actor::next_event). Actors with timers,
//! network receivers, or other unboxed sources can override `next_event` and
//! race those sources directly against [`LaneSet::recv`]. Source ordering and
//! source exhaustion policy live in that hook.

use commonware_utils::NZUsize;
use std::num::NonZeroUsize;

mod builder;
pub use builder::{Builder, MultiLaneBuilder};

mod driver;

mod metrics;

mod reliable;
pub use reliable::Reliable;

mod types;
pub use types::{DuplicateLaneError, Event, Lane, LaneEvent, LaneReceiver, LaneSet, Lanes};

mod unreliable;
pub use unreliable::Unreliable;

/// Default mailbox capacity for single-lane services.
pub const DEFAULT_MAILBOX_CAPACITY: NonZeroUsize = NZUsize!(1024);

/// Ordering between read-write handlers and in-flight read-only handlers.
///
/// Read-only handlers execute on a snapshot captured when the message was
/// admitted. The fence mode controls the reverse direction: whether a
/// read-write handler waits for read-only handlers that were admitted before
/// it. In either mode, snapshots must remain immutable across concurrent
/// lifecycle hooks such as [`crate::Actor::preprocess`],
/// [`crate::Actor::postprocess`], and [`crate::Actor::next_event`].
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FenceMode {
    /// Drain every in-flight read-only handler before each read-write
    /// handler runs.
    ///
    /// A read admitted before a write completes its response and
    /// handler-owned work before that write executes, so no asker can observe
    /// a pre-write response arrive after the write has been acknowledged.
    /// Read handlers must honor the completion contract on
    /// [`crate::Actor::on_read_only`]. This is the strongest ordering and the
    /// default. Its cost is that one slow read stalls the write and all
    /// ingress behind it.
    #[default]
    Linearizable,
    /// Run read-write handlers immediately, concurrently with in-flight
    /// read-only handlers.
    ///
    /// Reads admitted before a write may respond after that write completes,
    /// using the snapshot captured at admission. With the required owned or
    /// immutable snapshot, responses remain self-consistent but can be stale
    /// relative to acknowledged writes.
    ///
    /// In addition to the lifecycle-hook requirement on [`FenceMode`], only
    /// use this mode when [`crate::Actor::Snapshot`] does not alias state that
    /// the read-write handler mutates. Otherwise a concurrent read can observe
    /// a partially-applied write.
    Snapshot,
}

/// Default maximum number of in-flight read-only handlers.
pub const DEFAULT_MAX_INFLIGHT_READS: NonZeroUsize = NZUsize!(16);

#[cfg(test)]
mod tests;
