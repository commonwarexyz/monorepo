use crate::{
    linked::{Context, Epoch},
    Broadcaster, Digest,
};
use bytes::Bytes;
use futures::{
    channel::{mpsc, oneshot},
    SinkExt,
};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    EnterEpoch {
        epoch: Epoch,
    },
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

impl Mailbox {
    pub async fn enter_epoch(&mut self, epoch: u64) {
        self.sender
            .send(Message::EnterEpoch { epoch })
            .await
            .expect("Failed to send enter epoch");
    }
}

impl Broadcaster for Mailbox {
    type Context = Context;
    type Digest = Digest;

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
