use crate::simplex::{signing_scheme::Scheme, types::Voter};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

pub enum Message<S: Scheme, D: Digest> {
    Batcher(Voter<S, D>),
    Resolver(Voter<S, D>),
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn from_batcher(&mut self, voter: Voter<S, D>) {
        self.send(Message::Batcher(voter)).await;
    }

    pub async fn from_resolver(&mut self, voter: Voter<S, D>) {
        self.send(Message::Resolver(voter)).await;
    }

    async fn send(&mut self, message: Message<S, D>) {
        if let Err(err) = self.sender.send(message).await {
            error!(?err, "failed to send verified voter");
        }
    }
}
