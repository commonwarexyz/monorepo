use crate::simplex::{signing_scheme::Scheme, types::Voter};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, stream, SinkExt};
use tracing::error;

// If either of these requests fails, it will not send a reply.
pub enum Message<S: Scheme, D: Digest> {
    Verified(Voter<S, D>),
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn verified(&mut self, voters: Vec<Voter<S, D>>) {
        if let Err(err) = self
            .sender
            .send_all(&mut stream::iter(
                voters.into_iter().map(|voter| Ok(Message::Verified(voter))),
            ))
            .await
        {
            error!(?err, "failed to send batch of voters");
        }
    }
}
