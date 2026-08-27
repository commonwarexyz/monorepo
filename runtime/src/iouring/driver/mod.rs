//! The io_uring driver: the owned event loop and ring ([Driver]) and the
//! shared op state that futures submit through ([Handle]).
//!
//! See [crate::iouring] for the full request flow and liveness discussion.

mod event_loop;
pub use event_loop::MAX_RING_SIZE;
pub(crate) use event_loop::{Driver, validate_ring_config};
mod handle;
pub(crate) use handle::{AcceptTicket, Affine, Handle, Ops, current_thread_id};
mod request;
pub(crate) use request::{Cache, RawSocketAddr};
pub(crate) mod spinner;
mod timeout;
use timeout::Tick;
mod waiter;
use waiter::WaiterId;
pub(crate) mod waker;
use event_loop::UserData;

#[cfg(test)]
pub(crate) mod testing;
