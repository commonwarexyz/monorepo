use crate::simplex::{
    signing_scheme::Scheme,
    types::{Notarization, Nullification},
};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

pub enum Message<S: Scheme, D: Digest> {
    Notarized { notarization: Notarization<S, D> },
    Nullified { nullification: Nullification<S> },
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn notarized(&mut self, notarization: Notarization<S, D>) {
        if let Err(err) = self.sender.send(Message::Notarized { notarization }).await {
            error!(?err, "failed to send notarization message");
        }
    }

    pub async fn nullified(&mut self, nullification: Nullification<S>) {
        if let Err(err) = self.sender.send(Message::Nullified { nullification }).await {
            error!(?err, "failed to send nullification message");
        }
    }
}
