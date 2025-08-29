use crate::{
    simplex::types::{Notarization, Nullification},
    types::View,
    Viewable,
};
use commonware_cryptography::{Digest, Signature};
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message<S: Signature, D: Digest> {
    Notarization(Notarization<S, D>),
    Nullification(Nullification<S>),
}

impl<S: Signature, D: Digest> Viewable for Message<S, D> {
    type View = View;

    fn view(&self) -> View {
        match self {
            Message::Notarization(notarization) => notarization.view(),
            Message::Nullification(nullification) => nullification.view(),
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<S: Signature, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Signature, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn notarization(&mut self, notarization: Notarization<S, D>) {
        self.sender
            .send(Message::Notarization(notarization))
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullification(&mut self, nullification: Nullification<S>) {
        self.sender
            .send(Message::Nullification(nullification))
            .await
            .expect("Failed to send nullification");
    }
}
