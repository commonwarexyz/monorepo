//! Utilities for working with channels and actor mailboxes.

use std::collections::VecDeque;

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

    /// Retain `message` behind the bounded ready queue.
    pub fn retain<T>(queue: &mut VecDeque<T>, message: T) -> Self {
        queue.push_back(message);
        Self::Backoff
    }

    /// Retain the message if it could not replace existing work.
    pub fn replace_or_retain<T>(result: Result<(), T>, queue: &mut VecDeque<T>) -> Self {
        match result {
            Ok(()) => Self::Backoff,
            Err(message) => Self::retain(queue, message),
        }
    }

    /// Drop the message if it could not replace existing work.
    pub fn replace_or_drop<T>(result: Result<(), T>) -> Self {
        match result {
            Ok(()) => Self::Backoff,
            Err(_) => Self::Dropped,
        }
    }
}
