//! Utilities for working with channels.

pub mod fallible;
mod reservation;
pub mod ring;
pub mod tracked;

pub use reservation::{ChannelExt, Reservation, Reserved};
pub use tokio::sync::{mpsc, oneshot};
