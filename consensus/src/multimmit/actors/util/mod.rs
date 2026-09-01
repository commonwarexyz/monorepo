//! Mechanics shared by Multimmit actors.
//!
//! - [`offload`](fn@offload): runs CPU-bound work on a strategy's worker pool and catches worker
//!   panics.
//! - [`gated`] and [`some_or_pending`]: keep a disabled or closed `select!` source quiet.
//! - [`ask`](fn@ask): sends a request that carries its reply channel and awaits the reply.
//! - [`Completion`]: resolves when an accepted request finishes.
//! - [`Waiters`]: callers that share one unit of work per key.
//! - [`reliable_policy`]: a mailbox policy that retains every overflowing message.
//! - [`Handler`]: forwards `commonware-resolver` requests to an actor mailbox.

mod ask;
mod completion;
mod gate;
mod handler;
mod offload;
mod policy;
mod waiters;

pub(crate) use ask::{ask, ask_unreliable};
pub use completion::Completion;
pub(crate) use gate::{gated, some_or_pending};
pub(crate) use handler::{Handler, HandlerMessage};
pub(crate) use offload::{Timing, WorkerPanicked, offload, offload_timed};
pub(crate) use policy::reliable_policy;
pub(crate) use waiters::Waiters;
