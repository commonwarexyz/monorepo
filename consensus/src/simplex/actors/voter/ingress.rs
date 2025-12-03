use crate::simplex::{signing_scheme::Scheme, types::Voter};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Voter<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub const fn new(sender: mpsc::Sender<Voter<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn verified(&mut self, voter: Voter<S, D>) {
        if let Err(err) = self.sender.send(voter).await {
            error!(?err, "failed to send batch of voters");
        }
    }
}
