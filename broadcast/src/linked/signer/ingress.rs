use crate::{linked::Context, Broadcaster};
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
    Verified {
        context: Context,
        payload: D,
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

impl<D: Digest> Mailbox<D> {
    pub async fn verified(&mut self, context: Context, payload: D) {
        self.sender
            .send(Message::Verified { context, payload })
            .await
            .expect("Failed to send verified");
    }
}

impl<D: Digest> Broadcaster for Mailbox<D> {
    type Context = Context;
    type Digest = D;

    async fn broadcast(&mut self, payload: Self::Digest) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Broadcast {
                payload,
                result: sender,
            })
            .await
            .expect("Failed to send broadcast");
        receiver
    }
}
