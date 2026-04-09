//! Utilities for working with channels.

pub mod fallible;
pub mod mpsc;
pub mod ring;
pub mod tracked;

pub use tokio::sync::oneshot;
