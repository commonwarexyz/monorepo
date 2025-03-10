//! Disseminate data over a wide-area network.

use commonware_utils::Array;
use std::future::Future;

/// Broadcaster is the interface responsible for replication of messages across a network.
pub trait Broadcaster: Clone + Send + 'static {
    /// Digest is an arbitrary hash digest.
    type Digest: Array;

    /// Attempt to broadcast a digest to the network.
    ///
    /// Returns a future that resolves to a boolean indicating success.
    /// The broadcast may fail for a variety of reasons such-as networking errors, the node not
    /// being a valid sequencer, or the Broadcaster not being ready to broadcast a new payload.
    fn broadcast(&mut self, payload: Self::Digest) -> impl Future<Output = ()> + Send;
}
