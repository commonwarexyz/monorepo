use crate::simplex::{signing_scheme::Scheme, types::Voter};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Source {
    Internal,
    Resolver,
}

#[derive(Clone)]
pub struct Message<S: Scheme, D: Digest> {
    source: Source,
    voter: Voter<S, D>,
}

impl<S: Scheme, D: Digest> Message<S, D> {
    pub fn new(source: Source, voter: Voter<S, D>) -> Self {
        Self { source, voter }
    }

    pub fn into_inner(self) -> (Source, Voter<S, D>) {
        (self.source, self.voter)
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn verified(&mut self, voter: Voter<S, D>) {
        self.send(Message::new(Source::Internal, voter)).await;
    }

    pub async fn from_resolver(&mut self, voter: Voter<S, D>) {
        self.send(Message::new(Source::Resolver, voter)).await;
    }

    async fn send(&mut self, message: Message<S, D>) {
        if let Err(err) = self.sender.send(message).await {
            error!(?err, "failed to send verified voter");
        }
    }
}
