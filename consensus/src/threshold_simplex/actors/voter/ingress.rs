use crate::threshold_simplex::wire;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    Notarization { notarization: wire::Notarization },
    Nullification { nullification: wire::Nullification },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn notarization(&mut self, notarization: wire::Notarization) {
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
