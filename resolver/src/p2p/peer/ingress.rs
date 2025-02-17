use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

use crate::{Client, Key};

pub enum Message<K> {
    Fetch {
        key: K,
        response: oneshot::Sender<Bytes>,
    },
}

#[derive(Clone)]
pub struct Mailbox<K> {
    sender: mpsc::Sender<Message<K>>,
}

impl<K> Mailbox<K> {
    pub(super) fn new(sender: mpsc::Sender<Message<K>>) -> Self {
        Self { sender }
    }
}

impl<K: Key> Client for Mailbox<K> {
    type Key = K;

    async fn fetch(&mut self, key: Self::Key) -> oneshot::Receiver<Bytes> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Fetch {
                key,
                response: sender,
            })
            .await
            .expect("Failed to send notarization");
        receiver
    }
}
