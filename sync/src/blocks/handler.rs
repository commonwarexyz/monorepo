use super::key::MultiIndex;
use bytes::Bytes;
use commonware_resolver::{p2p::Producer, Consumer};
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

pub enum Message {
    Deliver {
        key: MultiIndex,
        value: Bytes,
        response: oneshot::Sender<bool>,
    },
    Produce {
        key: MultiIndex,
        response: oneshot::Sender<Bytes>,
    },
}

/// Mailbox for resolver
#[derive(Clone)]
pub struct Handler {
    sender: mpsc::Sender<Message>,
}

impl Handler {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Consumer for Handler {
    type Key = MultiIndex;
    type Value = Bytes;
    type Failure = ();

    async fn deliver(&mut self, key: Self::Key, value: Self::Value) -> bool {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Deliver {
                key,
                value,
                response,
            })
            .await
            .expect("Failed to send deliver");
        receiver.await.expect("Failed to receive deliver")
    }

    async fn failed(&mut self, _: Self::Key, _: Self::Failure) {
        // Ignore any failure
    }
}

impl Producer for Handler {
    type Key = MultiIndex;

    async fn produce(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (response, receiver) = oneshot::channel();
        self.sender
            .send(Message::Produce { key, response })
            .await
            .expect("Failed to send produce");
        receiver
    }
}
