//! Disseminate data over a wide-area network.

#![doc(
    html_logo_url = "https://commonware.xyz/imgs/rustdoc_logo.svg",
    html_favicon_url = "https://commonware.xyz/favicon.ico"
)]

use commonware_codec::Codec;
use futures::channel::oneshot;
use std::future::Future;

pub mod buffered;

/// Broadcaster is the interface responsible for attempting replication of messages across a network.
pub trait Broadcaster: Clone + Send + 'static {
    /// The type of recipients that can receive messages.
    type Recipients;

    /// Message is the type of data that can be broadcasted.
    ///
    /// It must implement the Codec trait so that it can be:
    /// - serialized upon broadcast
    /// - deserialized upon reception
    type Message: Codec + Clone + Send + 'static;

    /// The type of data that is returned once the message is broadcasted.
    ///
    /// It may also indicate the success or failure of the broadcast attempt.
    type Response: Clone + Send + 'static;

    /// Attempt to broadcast a message to the associated recipients.
    fn broadcast(
        &mut self,
        recipients: Self::Recipients,
        message: Self::Message,
    ) -> impl Future<Output = oneshot::Receiver<Self::Response>> + Send;
}
