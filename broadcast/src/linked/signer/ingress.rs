use std::marker::PhantomData;

use crate::{linked::Context, Broadcaster};
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

// If either of these requests fails, it will not send a reply.
pub enum Message<D: Digest> {
    Broadcast {
        payload_digest: D,
        result: oneshot::Sender<bool>,
    },
    Verified {
        context: Context,
        payload_digest: D,
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
    type Context = Context;
    type Digest = D;

    async fn broadcast(&mut self, payload_digest: Self::Digest) -> oneshot::Receiver<bool> {
        let (sender, receiver) = oneshot::channel();
        self.sender
            .send(Message::Broadcast {
                payload_digest,
                result: sender,
            })
            .await
            .expect("Failed to send broadcast");
        receiver
    }

    async fn verified(&mut self, context: Self::Context, payload_digest: Self::Digest) {
        self.sender
            .send(Message::Verified {
                context,
                payload_digest,
            })
            .await
            .expect("Failed to send verified");
    }
}
