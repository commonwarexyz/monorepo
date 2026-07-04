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
//! snapshot of actor state captured when its message was admitted, so it
//! never observes a partially-applied write. Consecutive reads admitted
//! without an intervening actor mutation share one snapshot capture.
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
//! Reads never observe writes admitted after them: a snapshot is fixed at
//! admission. [`FenceMode`] controls the reverse direction, whether a write
//! waits for reads admitted before it:
//!
//! - [`FenceMode::Linearizable`] (default) drains every in-flight read before
//!   a write runs. A read admitted before a write always responds before that
//!   write executes, so no caller can observe a pre-write response arrive
//!   after the write has been acknowledged. The cost is that one slow read
//!   stalls the write and all ingress behind it.
//! - [`FenceMode::Snapshot`] runs writes immediately, concurrently with
//!   in-flight reads. Reads still respond with the snapshot captured at
//!   admission, so responses are always self-consistent, but they can be
//!   stale relative to acknowledged writes.
//!
//! Within one lane, messages are processed in enqueue order. Across lanes,
//! selection is declaration-order biased (see [`Builder`]).
//!
//! # Shutdown
//!
//! Shutdown (runtime stop, [`Event::Stop`], or a fatal handler error) is
//! prompt: in-flight read-only handlers are aborted before
//! [`Actor::on_shutdown`](crate::Actor::on_shutdown) runs, and their pending
//! askers observe [`Cancelled`](crate::ingress::Cancelled).
//!
//! # Event Sources
//!
//! Actors that only need mailbox input can use the default
//! [`Actor::next_event`](crate::Actor::next_event). Actors with timers,
//! network receivers, or other unboxed sources can override `next_event` and
//! race those sources directly against [`LaneSet::recv`]. Source ordering and
//! source exhaustion policy live in that hook.

use crate::ingress::IntoEnvelope;
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
/// Read-only handlers always execute on a snapshot captured when the message
/// was admitted, so they never observe a partially-applied write. The fence
/// mode controls the reverse direction: whether a read-write handler waits
/// for read-only handlers that were admitted before it.
#[derive(Clone, Copy, Debug, Default, PartialEq, Eq)]
pub enum FenceMode {
    /// Drain every in-flight read-only handler before each read-write
    /// handler runs.
    ///
    /// A read admitted before a write always responds before that write
    /// executes, so no asker can observe a pre-write response arrive after
    /// the write has been acknowledged. This is the strongest ordering and
    /// the default. Its cost is that one slow read stalls the write and all
    /// ingress behind it.
    #[default]
    Linearizable,
    /// Run read-write handlers immediately, concurrently with in-flight
    /// read-only handlers.
    ///
    /// Reads admitted before a write may respond after that write completes,
    /// using the snapshot captured at admission. Responses are always
    /// snapshot-consistent but can be stale relative to acknowledged writes.
    ///
    /// Only use this mode when [`crate::Actor::Snapshot`] is an owned or
    /// immutable view of actor state. If the snapshot aliases state the
    /// write mutates (e.g. through a shared lock), a concurrent read can
    /// observe a partially-applied write.
    Snapshot,
}

/// Default maximum number of in-flight read-only handlers.
pub const DEFAULT_MAX_INFLIGHT_READS: NonZeroUsize = NZUsize!(16);

/// Ingress accepted by the actor service loop.
///
/// Builders select whether lanes are backed by [`crate::mailbox::Policy`] or
/// [`crate::mailbox::UnreliablePolicy`].
pub trait Ingress: IntoEnvelope {}

impl<I> Ingress for I where I: IntoEnvelope {}

#[cfg(test)]
mod tests;
