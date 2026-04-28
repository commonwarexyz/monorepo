//! Utilities for working with channels.

pub mod fallible;
pub mod reservation;
pub mod ring;
pub mod tracked;

pub use tokio::sync::{mpsc, oneshot};
