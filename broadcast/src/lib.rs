//! Disseminate data over a wide-area network.

use commonware_codec::Codec;
use std::future::Future;

pub mod buffered;

/// Broadcaster is the interface responsible for attempting replication of messages across a network.
pub trait Broadcaster<C>: Clone + Send + 'static {
    /// Message is the type of data that can be broadcasted.
    ///
    /// It must implement the Codec trait so that it can be:
    /// - serialized upon broadcast
    /// - deserialized upon reception
    type Message: Codec<C> + Clone + Send + 'static;

    /// Attempt to broadcast a message to the network.
    fn broadcast(&mut self, message: Self::Message) -> impl Future<Output = ()> + Send;
}
