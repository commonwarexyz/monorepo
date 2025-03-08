//! Disseminate data over a wide-area network.

use commonware_codec::Codec;
use std::future::Future;

pub mod buffered;

/// Broadcaster is the interface responsible for attempting replication of messages across a network.
pub trait Broadcaster: Clone + Send + 'static {
    /// Blob is the type of data that can be broadcasted.
    ///
    /// It must implement the Codec trait so that it can be:
    /// - serialized upon broadcast
    /// - deserialized upon reception
    type Blob: Codec + Clone + Send + 'static;

    /// Attempt to broadcast a blob to the network.
    fn broadcast(&mut self, payload: Self::Blob) -> impl Future<Output = ()> + Send;
}
