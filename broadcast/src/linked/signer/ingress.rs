use crate::Broadcaster;
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};
use std::marker::PhantomData;

// If either of these requests fails, it will not send a reply.
pub enum Message<D: Digest> {
    Broadcast {
        payload: D,
        result: oneshot::Sender<bool>,
    },
}

#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
    _digest: PhantomData<D>,
}

impl<D: Digest> Mailbox<D> {
    pub(super) fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self {
            sender,
            _digest: PhantomData,
        }
    }
}

impl<D: Digest> Broadcaster for Mailbox<D> {
    type Digest = D;

    async fn broadcast(&mut self, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        let _ = self
            .sender
            .send(Message::Broadcast {
                payload,
                result: sender,
            })
            .await;
        receiver
    }
}
