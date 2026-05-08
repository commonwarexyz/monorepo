//! Utilities for working with channels and actor mailboxes.

pub mod actor;
pub mod fallible;
pub mod reservation;
pub mod ring;
pub mod tracked;

pub use tokio::sync::{mpsc, oneshot};

/// Feedback from submitting work to a bounded endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Feedback {
    /// The work was accepted immediately.
    Ok,
    /// The endpoint is applying backpressure, but retained some work.
    Backoff,
    /// The work was dropped by policy.
    Dropped,
    /// The endpoint has closed.
    Closed,
}

impl Feedback {
    /// Returns true if the work was accepted.
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Ok | Self::Backoff)
    }
}
