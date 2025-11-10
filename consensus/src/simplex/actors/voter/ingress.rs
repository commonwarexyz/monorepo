use crate::{
    simplex::{
        signing_scheme::Scheme,
        types::{Finalization, Notarization, Notarize, Nullification},
    },
    types::View,
};
use commonware_cryptography::Digest;
use futures::{channel::mpsc, SinkExt};
use tracing::error;

pub enum Message<S: Scheme, D: Digest> {
    LeaderNotarize(Notarize<S, D>),
    Notarization(Notarization<S, D>),
    Nullification(Nullification<S>),
    Finalization(Finalization<S, D>),
    NotarizeSupport { view: View },
}

#[derive(Clone)]
pub struct Mailbox<S: Scheme, D: Digest> {
    sender: mpsc::Sender<Message<S, D>>,
}

impl<S: Scheme, D: Digest> Mailbox<S, D> {
    pub fn new(sender: mpsc::Sender<Message<S, D>>) -> Self {
        Self { sender }
    }

    pub async fn send(&mut self, message: Message<S, D>) {
        if let Err(err) = self.sender.send(message).await {
            error!(?err, "failed to send message to voter");
        }
    }
}
