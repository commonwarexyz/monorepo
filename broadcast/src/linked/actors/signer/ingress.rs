use crate::linked::wire;
use futures::{channel::mpsc, SinkExt};

// If either of these requests fails, it will not send a reply.
pub enum Message {
    BroadcastCar { car: wire::Car },
    RequestProvenCar { request: wire::Backfill },
}

#[derive(Clone)]
pub struct Mailbox {
    sender: mpsc::Sender<Message>,
}

impl Mailbox {
    pub(super) fn new(sender: mpsc::Sender<Message>) -> Self {
        Self { sender }
    }

    pub async fn broadcast_car(&mut self, car: wire::Car) {
        self.sender
            .send(Message::BroadcastCar { car })
            .await
            .expect("Failed to send car");
    }

    pub async fn request_proven_car(&mut self, request: wire::Backfill) {
        self.sender
            .send(Message::RequestProvenCar { request })
            .await
            .expect("Failed to send proven car request");
    }
}
