use crate::simplex::types::{Notarization, Nullification};
use commonware_cryptography::{Digest, Verifier};
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message<V: Verifier, D: Digest> {
    Notarization(Notarization<V, D>),
    Nullification(Nullification<V>),
}

#[derive(Clone)]
pub struct Mailbox<V: Verifier, D: Digest> {
    sender: mpsc::Sender<Message<V, D>>,
}

impl<V: Verifier, D: Digest> Mailbox<V, D> {
    pub(super) fn new(sender: mpsc::Sender<Message<V, D>>) -> Self {
        Self { sender }
    }

    pub async fn notarization(&mut self, notarization: Notarization<V, D>) {
        self.sender
            .send(Message::Notarization(notarization))
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullification(&mut self, nullification: Nullification<V>) {
        self.sender
            .send(Message::Nullification(nullification))
            .await
            .expect("Failed to send nullification");
    }
}
