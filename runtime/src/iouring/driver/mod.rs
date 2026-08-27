//! The io_uring driver: the owned event loop and ring ([Driver]) and the
//! shared op state that futures submit through ([Handle]).
//!
//! See [crate::iouring] for the full request flow and liveness discussion.

mod callbacks;
mod capacity;
mod event_loop;
pub use event_loop::MAX_RING_SIZE;
pub(crate) use event_loop::{Driver, validate_ring_config};
mod handle;
pub(crate) use handle::{AcceptTicket, Affine, Handle, current_thread_id};
mod request;
pub(crate) use request::Cache;
mod spinner;
pub use spinner::Config as SpinnerConfig;
mod timeout;
use timeout::Tick;
mod waiter;
use waiter::WaiterId;
mod waker;
pub(crate) use waker::Waker as RingWaker;
use event_loop::UserData;

#[cfg(test)]
pub(crate) mod testing;
