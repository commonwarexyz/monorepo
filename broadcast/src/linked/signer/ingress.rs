use crate::{linked::Context, Broadcaster};
use bytes::Bytes;
use commonware_cryptography::Digest;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    Broadcast {
        payload: Bytes,
        result: oneshot::Sender<bool>,
    },
    Verified {
        context: Context,
        payload_digest: Digest,
    },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }
}

impl Broadcaster for Mailbox {
    type Context = Context;

    async fn broadcast(&mut self, payload: Bytes) -> oneshot::Receiver<bool> {
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

    async fn verified(&mut self, context: Self::Context, payload_digest: Digest) {
        self.sender
            .send(Message::Verified {
                context,
                payload_digest,
            })
            .await
            .expect("Failed to send verified");
    }
}
