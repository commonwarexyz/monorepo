use crate::{actors::peer, channels::Channels, crypto::PublicKey};
use bytes::Bytes;
use tokio::sync::{mpsc, oneshot};

pub enum Message {
    Ready {
        peer: PublicKey,
        relay: peer::Relay,
        channels: oneshot::Sender<Channels>,
    },
    Release {
        peer: PublicKey,
    },
    Content {
        recipients: Vec<PublicKey>,
        channel: u32,
        message: Bytes,
        priority: bool,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn ready(&self, peer: PublicKey, relay: peer::Relay) -> Channels {
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

    pub async fn release(&self, peer: PublicKey) {
        self.sender.send(Message::Release { peer }).await.unwrap();
    }
}

#[derive(Clone)]
pub struct Messenger {
    sender: mpsc::Sender<Message>,
}

impl Messenger {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn content(
        &self,
        recipients: Vec<PublicKey>,
        channel: u32,
        message: Bytes,
        priority: bool,
    ) {
        self.sender
            .send(Message::Content {
                recipients,
                channel,
                message,
                priority,
            })
            .await
            .unwrap();
    }
}
