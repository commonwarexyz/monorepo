use crate::{
    authenticated::{data::Data, discovery::channels::Channels, relay::Relay, Mailbox},
    Channel, Recipients,
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use commonware_utils::channels::ring;
use futures::channel::oneshot;

/// Messages that can be processed by the router.
#[derive(Debug)]
pub enum Message<P: PublicKey> {
    /// Notify the router that a peer is ready to communicate.
    Ready {
        peer: P,
        relay: Relay<Data>,
        channels: oneshot::Sender<Channels<P>>,
    },
    /// Notify the router that a peer is no longer available.
    Release { peer: P },
    /// Send a message to one or more recipients.
    Content {
        recipients: Recipients<P>,
        channel: Channel,
        message: Bytes,
        priority: bool,
        success: oneshot::Sender<Vec<P>>,
    },
    /// Get a subscription to peers known by the router.
    SubscribePeers {
        response: oneshot::Sender<ring::Receiver<Vec<P>>>,
    },
}

impl<P: PublicKey> Mailbox<Message<P>> {
    /// Notify the router that a peer is ready to communicate.
    pub async fn ready(&mut self, peer: P, relay: Relay<Data>) -> Channels<P> {
        let (response, receiver) = oneshot::channel();
        self.send(Message::Ready {
            peer,
            relay,
            channels: response,
        })
        .await
        .unwrap();
        receiver.await.unwrap()
    }

    /// Notify the router that a peer is no longer available.
    ///
    /// This may fail during shutdown if the router has already exited,
    /// which is harmless since the router no longer tracks any peers.
    pub async fn release(&mut self, peer: P) {
        let _ = self.send(Message::Release { peer }).await;
    }
}

#[derive(Clone, Debug)]
/// Sends messages containing content to the router to send to peers.
pub struct Messenger<P: PublicKey> {
    sender: Mailbox<Message<P>>,
}

impl<P: PublicKey> Messenger<P> {
    /// Returns a new [Messenger] with the given sender.
    /// (The router has the corresponding receiver.)
    pub const fn new(sender: Mailbox<Message<P>>) -> Self {
        Self { sender }
    }

    /// Sends a message to the given `recipients`.
    pub async fn content(
        &mut self,
        recipients: Recipients<P>,
        channel: Channel,
        message: Bytes,
        priority: bool,
    ) -> Vec<P> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Content {
                recipients,
                channel,
                message,
                priority,
                success: sender,
            })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    /// Returns a subscription channel for the peers known to the router.
    pub async fn subscribe_peers(&mut self) -> ring::Receiver<Vec<P>> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::SubscribePeers { response: sender })
            .await
            .unwrap();
        receiver.await.unwrap()
    }
}
