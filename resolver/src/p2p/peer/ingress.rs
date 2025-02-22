use crate::Resolver;
use commonware_cryptography::Array;
use futures::{channel::mpsc, SinkExt};

/// Messages that can be sent to the peer actor.
pub enum Message<K> {
    Fetch { key: K },
    Cancel { key: K },
}

/// A way to send messages to the peer actor.
#[derive(Clone)]
pub struct Mailbox<K> {
    sender: mpsc::Sender<Message<K>>,
}

impl<K> Mailbox<K> {
    pub(super) fn new(sender: mpsc::Sender<Message<K>>) -> Self {
        Self { sender }
    }
}

impl<K: Array> Resolver for Mailbox<K> {
    type Key = K;

    async fn fetch(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Fetch { key })
            .await
            .expect("Failed to send fetch");
    }

    async fn cancel(&mut self, key: Self::Key) {
        self.sender
            .send(Message::Cancel { key })
            .await
            .expect("Failed to send cancel_fetch");
    }
}
