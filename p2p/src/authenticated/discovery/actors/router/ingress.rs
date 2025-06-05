use crate::{
    authenticated::{
        self,
        discovery::{channels::Channels, types},
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
        relay: authenticated::Relay<types::Data>,
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

impl<P: PublicKey> authenticated::Mailbox<Message<P>> {
    pub async fn ready(
        &mut self,
        peer: P,
        relay: authenticated::Relay<types::Data>,
    ) -> Channels<P> {
        let (response, receiver) = oneshot::channel();
        self.0
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
        self.0.send(Message::Release { peer }).await.unwrap();
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
