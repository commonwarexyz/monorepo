use commonware_cryptography::Digest;
use commonware_utils::Array;
use futures::{channel::mpsc, SinkExt};

use crate::threshold_simplex::types::{Notarization, Nullification};

// If either of these requests fails, it will not send a reply.
pub enum Message<D: Digest> {
    Notarization { notarization: Notarization<D> },
    Nullification { nullification: Nullification },
}

#[derive(Clone)]
pub struct Mailbox<D: Digest> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: Array> Mailbox<D> {
    pub(super) fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self { sender }
    }

    pub async fn notarization(&mut self, notarization: Notarization<D>) {
        self.sender
            .send(Message::Notarization { notarization })
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullification(&mut self, nullification: Nullification) {
        self.sender
            .send(Message::Nullification { nullification })
            .await
            .expect("Failed to send nullification");
    }
}
