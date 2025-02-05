use crate::{
    authenticated::{actors::peer, channels::Channels},
    Channel, Recipients,
};
use bytes::Bytes;
use commonware_cryptography::Component;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message<P: Component> {
    Ready {
        peer: P,
        relay: peer::Relay,
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
pub struct Mailbox<P: Component> {
    sender: mpsc::Sender<Message<P>>,
}

impl<P: Component> Mailbox<P> {
    pub fn new(sender: mpsc::Sender<Message<P>>) -> Self {
        Self { sender }
    }

    pub async fn ready(&mut self, peer: P, relay: peer::Relay) -> Channels<P> {
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
pub struct Messenger<P: Component> {
    sender: mpsc::Sender<Message<P>>,
}

impl<P: Component> Messenger<P> {
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
