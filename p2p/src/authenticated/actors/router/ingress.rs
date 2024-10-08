use crate::{
    authenticated::{actors::peer, channels::Channels},
    Recipients,
};
use bytes::Bytes;
use commonware_cryptography::PublicKey;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

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
        recipients: Recipients,
        channel: u32,
        message: Bytes,
        priority: bool,
        success: oneshot::Sender<Vec<PublicKey>>,
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

    pub async fn ready(&mut self, peer: PublicKey, relay: peer::Relay) -> Channels {
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

    pub async fn release(&mut self, peer: PublicKey) {
        self.sender.send(Message::Release { peer }).await.unwrap();
    }
}

#[derive(Clone, Debug)]
pub struct Messenger {
    sender: mpsc::Sender<Message>,
}

impl Messenger {
    pub fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn content(
        &mut self,
        recipients: Recipients,
        channel: u32,
        message: Bytes,
        priority: bool,
    ) -> Vec<PublicKey> {
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
