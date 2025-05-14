use crate::threshold_simplex::types::{Notarization, Nullification, View, Viewable, Voter};
use commonware_cryptography::{bls12381::primitives::variant::Variant, Digest};
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message<V: Variant, D: Digest> {
    Voter(Voter<V, D>),
    Notarization(Notarization<V, D>),
    Nullification(Nullification<V>),
}

impl<V: Variant, D: Digest> Viewable for Message<V, D> {
    fn view(&self) -> View {
        match self {
            Message::Voter(voter) => voter.view(),
            Message::Notarization(notarization) => notarization.view(),
            Message::Nullification(nullification) => nullification.view(),
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<V: Variant, D: Digest> {
    sender: mpsc::Sender<Message<V, D>>,
}

impl<V: Variant, D: Digest> Mailbox<V, D> {
    pub fn new(sender: mpsc::Sender<Message<V, D>>) -> Self {
        Self { sender }
    }

    pub async fn voter(&mut self, voter: Voter<V, D>) {
        self.sender
            .send(Message::Voter(voter))
            .await
            .expect("Failed to send voter");
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
