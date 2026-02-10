//! Connection management for authenticated peers.
//!
//! This module provides a [`Connection`] wrapper that bundles the sender,
//! receiver, and closer for a peer connection into a single value that
//! can be passed through channels.

use commonware_runtime::{Closer, Sink, Stream};
use commonware_stream::encrypted::{Receiver, Sender};

/// A connection to a peer.
///
/// Bundles the encrypted sender, receiver, and closer together so they
/// can be transferred as a single unit (e.g., through a spawner mailbox).
pub struct Connection<S: Sink, R: Stream, C: Closer> {
    sender: Sender<S>,
    receiver: Receiver<R>,
    closer: C,
}

impl<S: Sink, R: Stream, C: Closer> Connection<S, R, C> {
    /// Create a new connection from its parts.
    pub fn new(sender: Sender<S>, receiver: Receiver<R>, closer: C) -> Self {
        Self {
            sender,
            receiver,
            closer,
        }
    }

    /// Consume the connection and return its parts.
    pub fn into_parts(self) -> (Sender<S>, Receiver<R>, C) {
        (self.sender, self.receiver, self.closer)
    }
}
