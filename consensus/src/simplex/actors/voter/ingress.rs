use crate::simplex::{
    signing_scheme::Scheme,
    types::{Proposal, Voter},
};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

/// Messages sent to the voter from resolver and batcher.
pub enum Message<S: Scheme, D: Digest> {
    /// Certificate from resolver or batcher.
    Voter(Voter<S, D>),
    /// Leader's proposal from batcher.
    Proposal(Proposal<D>),
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
        if let Err(err) = self.sender.send(Message::Voter(voter)).await {
            error!(?err, "failed to send voter message");
        }
    }

    pub async fn proposal(&mut self, proposal: Proposal<D>) {
        if let Err(err) = self.sender.send(Message::Proposal(proposal)).await {
            error!(?err, "failed to send proposal message");
        }
    }
}
