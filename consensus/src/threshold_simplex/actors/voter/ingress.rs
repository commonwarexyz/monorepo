use crate::threshold_simplex::types::Voter;
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest};
use futures::{channel::mpsc, stream, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message<V: Variant, D: Digest> {
    Verified(Voter<V, D>),
}

#[derive(Clone)]
pub struct Mailbox<V: Variant, D: Digest> {
    sender: mpsc::Sender<Message<V, D>>,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    pub fn new(sender: mpsc::Sender<Message<V, D>>) -> Self {
        Self { sender }
    }

    pub async fn verified(&mut self, voters: Vec<Voter<V, D>>) {
        self.sender
            .send_all(&mut stream::iter(
                voters.into_iter().map(|voter| Ok(Message::Verified(voter))),
            ))
            .await
            .expect("Failed to send batch of voters");
    }
}
