use crate::threshold_simplex::types::{Notarization, Nullification, View, Viewable};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message<D: Digest> {
    Notarization(Notarization<D>),
    Nullification(Nullification),
}

impl<D: Digest> Viewable for Message<D> {
    fn view(&self) -> View {
        match self {
            Message::Notarization(notarization) => notarization.view(),
            Message::Nullification(nullification) => nullification.view(),
        }
    }
}

#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Digest> Mailbox<D> {
    pub fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self { sender }
    }

    pub async fn notarization(&mut self, notarization: Notarization<D>) {
        self.sender
            .send(Message::Notarization(notarization))
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullification(&mut self, nullification: Nullification) {
        self.sender
            .send(Message::Nullification(nullification))
            .await
            .expect("Failed to send nullification");
    }
}
