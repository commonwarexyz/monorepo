use crate::{linked::Context, Broadcaster, Error};
use bytes::Bytes;
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
        let msg = Message::Broadcast {
            payload,
            result: sender,
        };
        self.sender.send(msg).await.map_err(|_| Error::MailboxError);
        receiver
    }
}
