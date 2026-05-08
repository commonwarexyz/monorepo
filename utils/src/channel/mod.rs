//! Utilities for working with channels and actor mailboxes.

pub mod actor;
pub mod fallible;
pub mod reservation;
pub mod ring;
pub mod tracked;

pub use tokio::sync::{mpsc, oneshot};

/// Result of submitting work to a bounded endpoint.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Submission {
    /// The work was accepted immediately.
    Accepted,
    /// The work was accepted under backpressure.
    Backlogged,
    /// The work was dropped by policy.
    Dropped,
    /// The endpoint has closed.
    Closed,
}

impl Submission {
    /// Returns true if the work was accepted.
    pub const fn accepted(&self) -> bool {
        matches!(self, Self::Accepted | Self::Backlogged)
    }
}
