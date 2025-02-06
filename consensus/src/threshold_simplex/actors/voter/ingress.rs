use crate::{threshold_simplex::wire, Parsed};
use commonware_cryptography::FormattedBytes;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message<D: FormattedBytes> {
    Notarization {
        notarization: Parsed<wire::Notarization, D>,
    },
    Nullification {
        nullification: wire::Nullification,
    },
}

#[derive(Clone)]
pub struct Mailbox<D: FormattedBytes> {
    sender: mpsc::Sender<Message<D>>,
}

impl<D: FormattedBytes> Mailbox<D> {
    pub(super) fn new(sender: mpsc::Sender<Message<D>>) -> Self {
        Self { sender }
    }

    pub async fn notarization(&mut self, notarization: Parsed<wire::Notarization, D>) {
        self.sender
            .send(Message::Notarization { notarization })
            .await
            .expect("Failed to send notarization");
    }

    pub async fn nullification(&mut self, nullification: wire::Nullification) {
        self.sender
            .send(Message::Nullification { nullification })
            .await
            .expect("Failed to send nullification");
    }
}
