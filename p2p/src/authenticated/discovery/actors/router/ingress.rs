use crate::{
    authenticated::{
        discovery::{channels::Channels, types},
        relay::Relay,
    },
    Channel, Recipients,
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message<P: PublicKey> {
    Ready {
        peer: P,
        relay: Relay<types::Data>,
        channels: oneshot::Sender<Channels<P>>,
    },
    Release {
        peer: P,
    },
    Content {
        recipients: Recipients<P>,
        channel: Channel,
        message: Bytes,
        priority: bool,
        success: oneshot::Sender<Vec<P>>,
    },
}

#[derive(Clone)]
/// Sends messages to a router to notify it about peer availability.
pub struct Mailbox<P: PublicKey> {
    sender: mpsc::Sender<Message<P>>,
}

impl<P: PublicKey> Mailbox<P> {
    /// Returns a new [Mailbox] with the given sender.
    /// (The router has the corresponding receiver.)
    pub fn new(sender: mpsc::Sender<Message<P>>) -> Self {
        Self { sender }
    }

    pub async fn ready(&mut self, peer: P, relay: Relay<types::Data>) -> Channels<P> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Ready {
                peer,
                relay,
                channels: response,
            })
            .await
            .unwrap();
        receiver.await.unwrap()
    }

    pub async fn release(&mut self, peer: P) {
        self.sender.send(Message::Release { peer }).await.unwrap();
    }
}

#[derive(Clone, Debug)]
pub struct Messenger<P: PublicKey> {
    sender: mpsc::Sender<Message<P>>,
}

impl<P: PublicKey> Messenger<P> {
    pub fn new(sender: mpsc::Sender<Message<P>>) -> Self {
        Self { sender }
    }

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
}
